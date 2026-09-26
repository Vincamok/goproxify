// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/proxy"
)

const (
	portalReplicaPath     = "/internal/v1/portal/replica"
	portalReplicaMaxBytes = 32 << 20
	portalReplicaDebounce = 250 * time.Millisecond
)

// portalReplicator envoie l'état du portail aux passerelles du groupe HA dès qu'il change,
// en regroupant les modifications rapprochées.
type portalReplicator struct {
	mu    sync.Mutex
	timer *time.Timer
}

func (s *Server) schedulePortalReplicaPush() {
	r := s.portalRepl
	if r == nil {
		return
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		return
	}
	r.timer = time.AfterFunc(portalReplicaDebounce, func() {
		r.mu.Lock()
		r.timer = nil
		r.mu.Unlock()
		s.pushPortalReplica(context.Background())
	})
}

// haPortalPeers retourne les passerelles pairs qui sont membres du groupe HA du portail.
func (s *Server) haPortalPeers(members []string) []proxy.PeerInfo {
	if s.peers == nil {
		return nil
	}
	var out []proxy.PeerInfo
	for _, p := range s.peers.All() {
		if isPortalMember(p.Name, members) && !strings.EqualFold(p.Name, s.cfg.Identity.NodeName) {
			out = append(out, p)
		}
	}
	return out
}

func isPortalMember(name string, members []string) bool {
	for _, m := range members {
		if strings.EqualFold(strings.TrimSpace(m), strings.TrimSpace(name)) {
			return true
		}
	}
	return false
}

// pushPortalReplica envoie l'état chiffré du portail à chaque pair du groupe.
func (s *Server) pushPortalReplica(ctx context.Context) {
	if s.portal == nil {
		return
	}
	store, key, members, shared, ok := s.portal.ReplicaInfo()
	if !ok {
		return
	}
	sealed, err := portal.SealReplica(store.ExportReplica(shared), key)
	if err != nil {
		s.log.Warn("portal: réplication — chiffrement impossible", "err", err)
		return
	}
	client := &http.Client{Timeout: 6 * time.Second}
	for _, p := range s.haPortalPeers(members) {
		p := p
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint+portalReplicaPath, bytes.NewReader(sealed))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := client.Do(req)
			if err != nil {
				s.log.Debug("portal: réplication — pair injoignable", "pair", p.Name, "err", err)
				return
			}
			resp.Body.Close()
		}()
	}
}

// syncPortalReplicaFromPeer récupère l'état du portail d'un pair du groupe HA et le fusionne.
func (s *Server) syncPortalReplicaFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.portal == nil {
		return
	}
	store, key, members, shared, ok := s.portal.ReplicaInfo()
	if !ok || !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+portalReplicaPath, nil)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, portalReplicaMaxBytes))
	if err != nil {
		return
	}
	s.mergePortalReplica(store, key, shared, data, p.Name)
}

func (s *Server) mergePortalReplica(store *portal.Store, key string, shared bool, sealed []byte, from string) bool {
	state, err := portal.OpenReplica(sealed, key)
	if err != nil {
		s.log.Warn("portal: réplication — état illisible (clé de groupe différente ?)", "pair", from, "err", err)
		return false
	}
	changed, err := store.MergeReplica(state, shared)
	if err != nil {
		s.log.Warn("portal: réplication — fusion", "pair", from, "err", err)
		return false
	}
	if changed {
		s.log.Info("portal: état répliqué depuis un pair du groupe HA", "pair", from)
	}
	return changed
}

// GET /internal/v1/portal/replica : état du portail, chiffré par la clé du groupe.
func (s *Server) handlePortalReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	store, key, _, shared, ok := s.portal.ReplicaInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sealed, err := portal.SealReplica(store.ExportReplica(shared), key)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// POST /internal/v1/portal/replica : un pair envoie son état (chiffré) ; il est fusionné.
func (s *Server) handlePortalReplicaImport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	store, key, _, shared, ok := s.portal.ReplicaInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, portalReplicaMaxBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state, err := portal.OpenReplica(data, key)
	if err != nil {
		http.Error(w, "état illisible", http.StatusBadRequest)
		return
	}
	if _, err := store.MergeReplica(state, shared); err != nil {
		http.Error(w, "fusion impossible", http.StatusInternalServerError)
		return
	}
	w.WriteHeader(http.StatusNoContent)
}
