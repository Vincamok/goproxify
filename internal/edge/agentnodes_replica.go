// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"

	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	"github.com/vincamok/goproxify/internal/edge/proxy"
)

// Liste et état des Agents partagés entre les passerelles d'un groupe HA (ADR 0014, étape 3). Chaque membre ne voit que
// les Agents qui lui parlent : celui qui a basculé est en ligne sur un membre et « hors ligne » sur l'autre. Un membre
// tire donc la liste de ses pairs à chaque tour de synchronisation et adopte les entrées plus récentes que les siennes,
// avec le nom du membre qui a vu l'Agent en dernier. Ces entrées servent à l'affichage et à l'acheminement des
// commandes : elles ne créent aucune connexion.

const (
	agentNodesReplicaPath     = "/internal/v1/agent/nodes/replica"
	agentNodesReplicaMaxBytes = 4 << 20
	agentNodesReplicaLabel    = "gpx-agent-nodes-replica|"
)

type agentNodesReplica struct {
	Nodes []edgeagent.NodeInfo `json:"nodes"`
}

// GET /internal/v1/agent/nodes/replica : les Agents connus de cette passerelle, chiffrés par la clé du groupe.
func (s *Server) handleAgentNodesReplicaExport(w http.ResponseWriter, r *http.Request) {
	if s.portal == nil {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	_, key, _, ok := s.portal.HAGroupInfo()
	if !ok {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	sealed, err := sealGroupJSON(agentNodesReplica{Nodes: s.ownedNodes()}, key, agentNodesReplicaLabel)
	if err != nil {
		http.Error(w, "réplication indisponible", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/octet-stream")
	_, _ = w.Write(sealed)
}

// syncAgentNodesFromPeer tire la liste des Agents d'un pair du groupe et adopte les entrées plus récentes.
func (s *Server) syncAgentNodesFromPeer(ctx context.Context, client *http.Client, p proxy.PeerInfo) {
	_, key, ok := s.haAgentPeers()
	if !ok {
		return
	}
	_, _, members, _ := s.portal.HAGroupInfo()
	if !isPortalMember(p.Name, members) {
		return
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, p.Endpoint+agentNodesReplicaPath, nil)
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
	data, err := io.ReadAll(io.LimitReader(resp.Body, agentNodesReplicaMaxBytes))
	if err != nil {
		return
	}
	s.mergeAgentNodesReplica(data, key, p.Name)
}

func (s *Server) mergeAgentNodesReplica(sealed []byte, key, from string) int {
	var doc agentNodesReplica
	if err := openGroupJSON(sealed, key, agentNodesReplicaLabel, &doc); err != nil {
		s.log.Warn("agents: liste des Agents d'un pair illisible (clé de groupe différente ?)", "pair", from, "err", err)
		return 0
	}
	adopted := s.nodeStore.Merge(doc.Nodes)
	if adopted > 0 {
		s.log.Debug("agents: liste des Agents mise à jour depuis un pair du groupe HA", "pair", from, "agents", adopted)
	}
	return adopted
}

// forwardAgentCommand transmet la commande à la passerelle du groupe qui a vu l'Agent en dernier, quand ce n'est pas
// celle-ci : c'est elle qui tient sa connexion. Vrai si la réponse du pair a été renvoyée ; faux pour tenter l'endpoint
// de l'Agent, comme avant (pair injoignable, Agent plus tenu par lui, commande déjà transmise).
func (s *Server) forwardAgentCommand(w http.ResponseWriter, r *http.Request, name string, body []byte) bool {
	if r.Header.Get("X-Gpx-Forwarded") != "" || s.cfg == nil {
		return false
	}
	n, ok := s.nodeStore.Get(name)
	if !ok || n.ConnectedVia == "" || strings.EqualFold(n.ConnectedVia, s.cfg.Identity.NodeName) {
		return false
	}
	peers, _, ok := s.haAgentPeers()
	if !ok {
		return false
	}
	for _, p := range peers {
		if !strings.EqualFold(p.Name, n.ConnectedVia) {
			continue
		}
		ctx, cancel := context.WithTimeout(r.Context(), 6*time.Second)
		defer cancel()
		req, err := http.NewRequestWithContext(ctx, http.MethodPost,
			p.Endpoint+"/internal/v1/agent/"+url.PathEscape(name)+"/command", bytes.NewReader(body))
		if err != nil {
			return false
		}
		req.Header.Set("Authorization", "Bearer "+p.Token)
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set("X-Gpx-Forwarded", "1")
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			s.log.Debug("agents: commande — pair injoignable", "pair", p.Name, "agent", name, "err", err)
			return false
		}
		defer resp.Body.Close()
		if resp.StatusCode >= 200 && resp.StatusCode < 300 {
			w.WriteHeader(resp.StatusCode)
			return true
		}
		return false
	}
	return false
}
