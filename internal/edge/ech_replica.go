// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

// Réplication des clés ECH entre les passerelles d'un groupe HA : une rotation reçue par un membre
// atteint les autres, et un membre redémarré les récupère d'un pair, sans l'Admin. Le jeu le plus
// récent l'emporte ; il est chiffré par la clé du groupe.

const (
	echReplicaPath     = "/internal/v1/ech/replica"
	echReplicaMaxBytes = 1 << 20
)

func (s *Server) sealECHReplica(key string) ([]byte, error) {
	return edgetls.SealECHReplica(edgetls.ECHReplica{Version: s.ech.Version(), Keys: s.ech.Keys()}, key)
}

// pushECHReplica envoie le jeu courant aux pairs du groupe, après un envoi de l'Admin.
func (s *Server) pushECHReplica(ctx context.Context) {
	peers, key, ok := s.haAgentPeers()
	if !ok || len(peers) == 0 || s.ech.Version() == 0 {
		return
	}
	sealed, err := s.sealECHReplica(key)
	if err != nil {
		s.log.Warn("ech: réplication — chiffrement impossible", "err", err)
		return
	}
	client := &http.Client{Timeout: 6 * time.Second}
	for _, p := range peers {
		p := p
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint+echReplicaPath, bytes.NewReader(sealed))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := client.Do(req)
			if err != nil {
				s.log.Debug("ech: réplication — pair injoignable", "pair", p.Name, "err", err)
				return
			}
			resp.Body.Close()
		}()
	}
}

// syncECHReplicaFromPeer récupère le jeu d'un pair du groupe et l'applique s'il est plus récent.
func (s *Server) syncECHReplicaFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	_, key, ok := s.haAgentPeers()
	if !ok {
		return
	}
	_, _, members, _ := s.portal.HAGroupInfo()
	if !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+echReplicaPath, nil)
	if err != nil {
		return
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := client.Do(req)
	if err != nil {
		return
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, echReplicaMaxBytes))
	if err != nil {
		return
	}
	s.mergeECHReplica(data, key, p.Name)
}

func (s *Server) mergeECHReplica(sealed []byte, key, from string) bool {
	r, err := edgetls.OpenECHReplica(sealed, key)
	if err != nil {
		s.log.Warn("ech: réplication — jeu illisible (clé de groupe différente ?)", "pair", from, "err", err)
		return false
	}
	changed, err := s.ech.Merge(r.Keys, r.Version)
	if err != nil {
		s.log.Warn("ech: réplication — fusion", "pair", from, "err", err)
		return false
	}
	if changed {
		s.saveCache()
		s.log.Info("ech: clés répliquées depuis un pair du groupe HA", "pair", from, "count", len(r.Keys))
	}
	return changed
}

// GET /internal/v1/ech/replica : jeu de clés ECH, chiffré par la clé du groupe.
func (s *Server) handleECHReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil || s.ech.Version() == 0 {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sealed, err := s.sealECHReplica(key)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// POST /internal/v1/ech/replica : un pair envoie son jeu (chiffré) ; il est appliqué s'il est plus récent.
func (s *Server) handleECHReplicaImport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, echReplicaMaxBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if _, err := edgetls.OpenECHReplica(data, key); err != nil {
		http.Error(w, "jeu illisible", http.StatusBadRequest)
		return
	}
	s.mergeECHReplica(data, key, "pair")
	w.WriteHeader(http.StatusNoContent)
}
