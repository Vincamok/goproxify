// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

// TypeEdgeEndpoints : la passerelle indique à l'Agent les adresses des autres membres de son groupe
// HA, pour qu'il bascule vers l'un d'eux si elle tombe.
const TypeEdgeEndpoints = "edge_endpoints"

// EdgeEndpointsPayload accompagne TypeEdgeEndpoints. La liste remplace la précédente.
type EdgeEndpointsPayload struct {
	Endpoints []string `json:"endpoints"`
}

// SetEdgeEndpointsProvider enregistre la fonction qui donne les adresses des autres membres du
// groupe HA de cette passerelle (vide hors groupe).
func (h *Hub) SetEdgeEndpointsProvider(fn func() []string) {
	h.mu.Lock()
	h.edgeEndpoints = fn
	h.mu.Unlock()
}

func (h *Hub) edgeEndpointsList() []string {
	h.mu.RLock()
	fn := h.edgeEndpoints
	h.mu.RUnlock()
	if fn == nil {
		return nil
	}
	return fn()
}

// sendEdgeEndpoints envoie à un Agent approuvé les adresses des autres membres du groupe.
func (h *Hub) sendEdgeEndpoints(ac *agentConn) {
	eps := h.edgeEndpointsList()
	if len(eps) == 0 {
		return
	}
	msg, err := NewMessage(ac.seq.Add(1), TypeEdgeEndpoints, EdgeEndpointsPayload{Endpoints: eps})
	if err != nil {
		return
	}
	if err := h.sendToAgent(ac, msg); err != nil {
		h.log.Debug("ws/agent: envoi des membres du groupe échoué", "agent", ac.id, "err", err)
	}
}

// BroadcastEdgeEndpoints renvoie la liste des membres à tous les Agents approuvés connectés
// (topologie du groupe modifiée).
func (h *Hub) BroadcastEdgeEndpoints() {
	if h == nil {
		return
	}
	h.mu.RLock()
	conns := make([]*agentConn, 0, len(h.agentConns))
	for _, ac := range h.agentConns {
		conns = append(conns, ac)
	}
	h.mu.RUnlock()
	for _, ac := range conns {
		ac.mu.Lock()
		approved := ac.approved
		ac.mu.Unlock()
		if approved {
			h.sendEdgeEndpoints(ac)
		}
	}
}
