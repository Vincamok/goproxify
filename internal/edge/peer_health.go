// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"net/http"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
)

const (
	peerProbeTimeout = 2 * time.Second
	// peerSyncBudget borne un tour entier : sans lui, un pair qui répond au sondage puis se tait coûte autant
	// de timeouts que d'appels de synchronisation.
	peerSyncBudget = 20 * time.Second
	peerRetryMax   = 2 * time.Minute
)

// peerHealth retient les pairs injoignables pour ne pas leur infliger, à chaque tour, la file complète des
// appels de synchronisation (chacun attend son timeout). Un pair en attente, sans trafic ni VRRP, est un cas
// normal : il est resondé de plus en plus rarement et resynchronisé dès qu'il répond.
type peerHealth struct {
	mu    sync.Mutex
	state map[string]*peerState
}

type peerState struct {
	fails int
	next  time.Time
}

// due dit si le pair doit être contacté à cet instant.
func (h *peerHealth) due(name string, now time.Time) bool {
	h.mu.Lock()
	defer h.mu.Unlock()
	st := h.state[name]
	return st == nil || !now.Before(st.next)
}

// record enregistre l'issue d'un tour. Après n échecs consécutifs, le prochain essai attend
// peerSyncInterval × 2^(n-1), au plus peerRetryMax.
func (h *peerHealth) record(name string, ok bool, now time.Time) {
	h.mu.Lock()
	defer h.mu.Unlock()
	if ok {
		delete(h.state, name)
		return
	}
	if h.state == nil {
		h.state = map[string]*peerState{}
	}
	st := h.state[name]
	if st == nil {
		st = &peerState{}
		h.state[name] = st
	}
	st.fails++
	delay := peerRetryMax
	if st.fails <= 4 {
		delay = min(peerSyncInterval<<(st.fails-1), peerRetryMax)
	}
	st.next = now.Add(delay)
}

// retain oublie les pairs qui ne sont plus dans la liste.
func (h *peerHealth) retain(peers []proxy.PeerInfo) {
	h.mu.Lock()
	defer h.mu.Unlock()
	for name := range h.state {
		found := false
		for _, p := range peers {
			if p.Name == name {
				found = true
				break
			}
		}
		if !found {
			delete(h.state, name)
		}
	}
}

// probePeer interroge l'état du pair : un seul appel court plutôt que toute la file de synchronisation.
func probePeer(ctx context.Context, p proxy.PeerInfo) bool {
	ctx, cancel := context.WithTimeout(ctx, peerProbeTimeout)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+"/internal/v1/health", nil)
	if err != nil {
		return false
	}
	req.Header.Set("Authorization", "Bearer "+p.Token)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return false
	}
	defer resp.Body.Close()
	return resp.StatusCode == http.StatusOK
}
