// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// syncThreatListsFromPeer récupère les listes de référence Sentinel (UA, chemins, IPs) d'une
// passerelle pair : la plus récente l'emporte (ApplyHAPayload), les passerelles d'un groupe HA
// convergent vers les mêmes listes.
func (s *Server) syncThreatListsFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	if s.threatEngine == nil {
		return
	}
	if payload, ok := fetchThreatLists(ctx, client, p.Endpoint, p.Token); ok {
		s.threatEngine.ApplyHAPayload(payload)
	}
}

func fetchThreatLists(ctx context.Context, client *http.Client, endpoint, token string) (threat.HAPayload, bool) {
	var payload threat.HAPayload
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint+"/internal/v1/threat-lists/export", nil)
	if err != nil {
		return payload, false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := client.Do(req)
	if err != nil {
		return payload, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return payload, false
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return payload, false
	}
	return payload, true
}
