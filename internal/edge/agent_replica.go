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

	"github.com/vincamok/goproxify/internal/edge/proxy"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Réplication des HMAC d'Agents entre les passerelles d'un groupe HA : un Agent approuvé sur un
// membre est accepté par tous, il peut donc basculer sur un autre si sa passerelle tombe, sans
// l'Admin. L'état est chiffré par la clé du groupe ; seuls les membres du groupe l'échangent.

const (
	agentReplicaPath     = "/internal/v1/agents/replica"
	agentReplicaMaxBytes = 4 << 20
	agentReplicaDebounce = 250 * time.Millisecond
)

type agentReplicator struct {
	mu    sync.Mutex
	timer *time.Timer
}

// haAgentPeers retourne les passerelles pairs membres du groupe HA de cette passerelle.
func (s *Server) haAgentPeers() (peers []proxy.PeerInfo, key string, ok bool) {
	if s.portal == nil || s.peers == nil {
		return nil, "", false
	}
	_, key, members, ok := s.portal.HAGroupInfo()
	if !ok {
		return nil, "", false
	}
	for _, p := range s.peers.All() {
		if isPortalMember(p.Name, members) && !strings.EqualFold(p.Name, s.cfg.Identity.NodeName) {
			peers = append(peers, p)
		}
	}
	return peers, key, true
}

// groupEdgeEndpoints retourne les adresses des autres membres du groupe HA : l'Agent bascule vers
// l'un d'eux si sa passerelle tombe. Vide hors groupe.
func (s *Server) groupEdgeEndpoints() []string {
	peers, _, ok := s.haAgentPeers()
	if !ok {
		return nil
	}
	out := make([]string, 0, len(peers))
	for _, p := range peers {
		if p.Endpoint != "" {
			out = append(out, p.Endpoint)
		}
	}
	return out
}

// scheduleAgentReplicaPush envoie les HMAC aux pairs du groupe après une modification locale, en
// regroupant les modifications rapprochées.
func (s *Server) scheduleAgentReplicaPush() {
	r := &s.agentRepl
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.timer != nil {
		return
	}
	r.timer = time.AfterFunc(agentReplicaDebounce, func() {
		r.mu.Lock()
		r.timer = nil
		r.mu.Unlock()
		s.pushAgentReplica(context.Background())
	})
}

func (s *Server) pushAgentReplica(ctx context.Context) {
	peers, key, ok := s.haAgentPeers()
	if !ok || len(peers) == 0 {
		return
	}
	sealed, err := edgews.SealHMACReplica(s.wsHub.HMACStore().Export(), key)
	if err != nil {
		s.log.Warn("agents: réplication — chiffrement impossible", "err", err)
		return
	}
	client := &http.Client{Timeout: 6 * time.Second}
	for _, p := range peers {
		p := p
		go func() {
			req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.Endpoint+agentReplicaPath, bytes.NewReader(sealed))
			if err != nil {
				return
			}
			req.Header.Set("Authorization", "Bearer "+p.Token)
			req.Header.Set("Content-Type", "application/octet-stream")
			resp, err := client.Do(req)
			if err != nil {
				s.log.Debug("agents: réplication — pair injoignable", "pair", p.Name, "err", err)
				return
			}
			resp.Body.Close()
		}()
	}
}

// syncAgentReplicaFromPeer récupère les HMAC d'un pair du groupe et les fusionne.
func (s *Server) syncAgentReplicaFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	_, key, ok := s.haAgentPeers()
	if !ok {
		return
	}
	_, _, members, _ := s.portal.HAGroupInfo()
	if !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+agentReplicaPath, nil)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, agentReplicaMaxBytes))
	if err != nil {
		return
	}
	s.mergeAgentReplica(data, key, p.Name)
}

func (s *Server) mergeAgentReplica(sealed []byte, key, from string) bool {
	state, err := edgews.OpenHMACReplica(sealed, key)
	if err != nil {
		s.log.Warn("agents: réplication — état illisible (clé de groupe différente ?)", "pair", from, "err", err)
		return false
	}
	return s.applyAgentReplica(state, from)
}

func (s *Server) applyAgentReplica(state edgews.HMACReplica, from string) bool {
	changed, removed, err := s.wsHub.HMACStore().Merge(state)
	if err != nil {
		s.log.Warn("agents: réplication — fusion", "pair", from, "err", err)
		return false
	}
	if len(removed) > 0 {
		s.wsHub.DisconnectAgents(removed)
	}
	if changed {
		s.log.Info("agents: HMAC répliqués depuis un pair du groupe HA", "pair", from)
	}
	return changed
}

// GET /internal/v1/agents/replica : HMAC des Agents, chiffrés par la clé du groupe.
func (s *Server) handleAgentReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sealed, err := edgews.SealHMACReplica(s.wsHub.HMACStore().Export(), key)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// POST /internal/v1/agents/replica : un pair envoie ses HMAC (chiffrés) ; ils sont fusionnés.
func (s *Server) handleAgentReplicaImport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	data, err := io.ReadAll(io.LimitReader(r.Body, agentReplicaMaxBytes))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	state, err := edgews.OpenHMACReplica(data, key)
	if err != nil {
		http.Error(w, "état illisible", http.StatusBadRequest)
		return
	}
	s.applyAgentReplica(state, "pair")
	w.WriteHeader(http.StatusNoContent)
}
