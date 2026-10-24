// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
)

// Proxys configurés partagés entre les passerelles d'un groupe HA (ADR 0014, étape 3). L'Admin publie chaque
// modification sur chaque passerelle, une par une : celle qui était absente garde l'ancienne version, et un proxy supprimé
// ailleurs reste chez elle. Un membre tire donc les proxys en production de ses pairs à chaque tour de synchronisation
// et adopte, pour chaque identifiant, ce qui est le plus récent : une version plus récente, ou une suppression plus
// récente que la version qu'il a. Les copies d'audit des révisions restent locales à chaque membre.

const (
	proxyReplicaPath     = "/internal/v1/replica/proxies"
	proxyReplicaMaxBytes = 64 << 20
	proxyReplicaLabel    = "gpx-proxy-replica|"
)

type proxyTombstone struct {
	ID        string    `json:"id"`
	DeletedAt time.Time `json:"deleted_at"`
}

type proxyReplica struct {
	Proxies    []*proxystore.Envelope `json:"proxies"`
	Tombstones []proxyTombstone       `json:"tombstones"`
}

func (s *Server) proxyReplicaDoc() proxyReplica {
	var doc proxyReplica
	if s.proxyStore == nil {
		return doc
	}
	if list, err := s.proxyStore.ListProd(); err == nil {
		doc.Proxies = list
	}
	for id, at := range s.proxyStore.Tombstones() {
		doc.Tombstones = append(doc.Tombstones, proxyTombstone{ID: id, DeletedAt: at})
	}
	sort.Slice(doc.Proxies, func(i, j int) bool { return doc.Proxies[i].ID < doc.Proxies[j].ID })
	sort.Slice(doc.Tombstones, func(i, j int) bool { return doc.Tombstones[i].ID < doc.Tombstones[j].ID })
	return doc
}

// digest résume les versions connues : deux membres au même condensé n'ont rien à s'échanger.
func (d proxyReplica) digest() string {
	h := sha256.New()
	for _, e := range d.Proxies {
		h.Write([]byte("p|" + e.ID + "|" + strconv.FormatInt(e.UpdatedAt.UnixNano(), 10) + "\n"))
	}
	for _, t := range d.Tombstones {
		h.Write([]byte("t|" + t.ID + "|" + strconv.FormatInt(t.DeletedAt.UnixNano(), 10) + "\n"))
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GET /internal/v1/replica/proxies : les proxys en production et les suppressions retenues, chiffrés par la clé du
// groupe. 304 si le demandeur a déjà les mêmes versions.
func (s *Server) handleProxyReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil || s.proxyStore == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	doc := s.proxyReplicaDoc()
	if r.Header.Get("If-None-Match") == `"`+doc.digest()+`"` {
		w.WriteHeader(http.StatusNotModified)
		return
	}
	sealed, err := sealGroupJSON(doc, key, proxyReplicaLabel)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// syncProxiesFromPeer tire les proxys d'un pair du groupe et adopte ce qui est plus récent que chez nous.
func (s *Server) syncProxiesFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.proxyStore == nil {
		return
	}
	_, key, ok := s.haAgentPeers()
	if !ok {
		return
	}
	_, _, members, _ := s.portal.HAGroupInfo()
	if !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+proxyReplicaPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	req.Header.Set("If-None-Match", `"`+s.proxyReplicaDoc().digest()+`"`)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, proxyReplicaMaxBytes))
	if err != nil {
		return
	}
	var doc proxyReplica
	if err := openGroupJSON(data, key, proxyReplicaLabel, &doc); err != nil {
		s.log.Warn("proxystore: réplication — document illisible (clé de groupe différente ?)", "pair", p.Name, "err", err)
		return
	}
	s.mergeProxyReplica(doc, p.Name)
}

// mergeProxyReplica adopte les proxys et suppressions d'un pair qui dépassent ce que ce membre a. Rend le nombre de
// changements appliqués.
func (s *Server) mergeProxyReplica(doc proxyReplica, from string) int {
	if s.proxyStore == nil {
		return 0
	}
	local := map[string]*proxystore.Envelope{}
	if list, err := s.proxyStore.ListProd(); err == nil {
		for _, e := range list {
			local[e.ID] = e
		}
	}
	tombs := s.proxyStore.Tombstones()
	changed := 0

	for _, t := range doc.Tombstones {
		if t.ID == "" {
			continue
		}
		if cur, ok := local[t.ID]; ok {
			if !t.DeletedAt.After(cur.UpdatedAt) {
				continue // notre version est plus récente que cette suppression
			}
			if err := s.removeFileProxy(t.ID, t.DeletedAt); err != nil {
				s.log.Warn("proxystore: réplication — suppression", "id", t.ID, "pair", from, "err", err)
				continue
			}
			delete(local, t.ID)
			tombs[t.ID] = t.DeletedAt
			changed++
			s.log.Info("proxystore: proxy supprimé d'après un pair du groupe HA", "id", t.ID, "pair", from)
			continue
		}
		if prev, ok := tombs[t.ID]; !ok || t.DeletedAt.After(prev) {
			_ = s.proxyStore.RecordTombstone(t.ID, t.DeletedAt)
			tombs[t.ID] = t.DeletedAt
		}
	}

	for _, e := range doc.Proxies {
		if e == nil || e.ID == "" || e.Status != proxystore.StatusProduction {
			continue
		}
		if at, deleted := tombs[e.ID]; deleted && !e.UpdatedAt.After(at) {
			continue // supprimé plus récemment que cette version
		}
		cur, have := local[e.ID]
		if have && !e.UpdatedAt.After(cur.UpdatedAt) {
			continue
		}
		if e.Enabled && !isImplicitRoute(e.ID) {
			if _, err := proxypipeline.ParseRoute(e); err != nil {
				s.log.Warn("proxystore: réplication — proxy refusé", "id", e.ID, "pair", from, "err", err)
				continue
			}
		}
		if err := s.proxyStore.WriteProd(e); err != nil {
			s.log.Warn("proxystore: réplication — écriture", "id", e.ID, "pair", from, "err", err)
			continue
		}
		if have {
			_ = s.proxyStore.RemoveProdIfRenamed(cur, e)
		}
		_ = s.proxyStore.ClearTombstone(e.ID)
		delete(tombs, e.ID)
		if err := s.ApplyFileProxy(e); err != nil {
			s.log.Warn("proxystore: réplication — application", "id", e.ID, "pair", from, "err", err)
		}
		changed++
		s.log.Info("proxystore: proxy adopté d'un pair du groupe HA", "id", e.ID, "host", e.Host, "pair", from)
	}

	if changed > 0 {
		metrics.Edge.RouteCount.Set(float64(s.table.Len()))
		s.saveCache()
	}
	return changed
}

// removeFileProxy retire un proxy du disque et de la table, et retient sa suppression (à la date donnée) pour les
// membres du groupe HA qui l'ignorent encore. Absent du disque : rien à faire, la suppression est retenue quand même.
func (s *Server) removeFileProxy(id string, at time.Time) error {
	if err := s.proxyStore.DeleteProdByID(id); err != nil && !errors.Is(err, proxystore.ErrNotFound) {
		return err
	}
	_ = s.proxyStore.RecordTombstone(id, at)
	if isImplicitRoute(id) {
		// Supprimer la surcouche rend la route à son générateur ; la route elle-même disparaît avec son réglage d'origine.
		s.refreshImplicitRoute(id)
		return nil
	}
	s.table.Delete(id)
	s.invalidateRouteCache(id)
	return nil
}
