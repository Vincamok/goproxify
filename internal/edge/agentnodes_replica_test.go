// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// La liste des Agents d'un membre atteint son pair, avec le membre qui les a vus.
func TestAgentNodesAreSharedWithGroupPeers(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := newStateNode(t, "frontal", groupKey, members), newStateNode(t, "backup", groupKey, members)
	link(a.haNode, b.haNode)
	a.srv.nodeStore.Upsert(edgeagent.NodeInfo{NodeName: "agent-1", Role: "agent", Version: "0.15.0", Endpoint: "http://10.0.0.5:8001"})

	client := &http.Client{Timeout: 3 * time.Second}
	b.srv.syncAgentNodesFromPeer(context.Background(), client, proxy.PeerInfo{Name: "frontal", Endpoint: a.http.URL, Token: "tok"})
	n, ok := b.srv.nodeStore.Get("agent-1")
	if !ok || n.Status != "online" || n.ConnectedVia != "frontal" || n.Version != "0.15.0" {
		t.Fatalf("B doit voir l'Agent de A, en ligne via frontal : %+v (connu %v)", n, ok)
	}

	// L'Agent bascule vers B : B le voit directement (ConnectedVia vide = lui-même), A l'apprend de B.
	b.srv.nodeStore.Upsert(edgeagent.NodeInfo{NodeName: "agent-1", Role: "agent", Version: "0.15.0"})
	a.srv.syncAgentNodesFromPeer(context.Background(), client, proxy.PeerInfo{Name: "backup", Endpoint: b.http.URL, Token: "tok"})
	if n, _ := a.srv.nodeStore.Get("agent-1"); n.ConnectedVia != "backup" {
		t.Fatalf("A doit apprendre que l'Agent est maintenant sur backup : %+v", n)
	}
}

// Le nom du membre qui a vu l'Agent est toujours renseigné pour l'Admin : celui de cette passerelle pour ses propres Agents.
func TestOwnedNodesNameTheGatewayThatSawThem(t *testing.T) {
	a := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	a.srv.nodeStore.Upsert(edgeagent.NodeInfo{NodeName: "agent-1", Role: "agent"})
	a.srv.nodeStore.Merge([]edgeagent.NodeInfo{{NodeName: "agent-2", Role: "agent", ConnectedVia: "backup", LastSeenAt: time.Now()}})
	via := map[string]string{}
	for _, n := range a.srv.ownedNodes() {
		via[n.NodeName] = n.ConnectedVia
	}
	if via["agent-1"] != "frontal" || via["agent-2"] != "backup" {
		t.Fatalf("connected_via = %v", via)
	}
}

// Un document d'une autre clé n'est pas cru.
func TestAgentNodesFromAnotherGroupAreIgnored(t *testing.T) {
	a := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	doc, err := sealGroupJSON(agentNodesReplica{Nodes: []edgeagent.NodeInfo{{NodeName: "intrus", Role: "agent", LastSeenAt: time.Now()}}}, "autre-cle", agentNodesReplicaLabel)
	if err != nil {
		t.Fatal(err)
	}
	if got := a.srv.mergeAgentNodesReplica(doc, groupKey, "pirate"); got != 0 {
		t.Fatalf("un document d'une autre clé est refusé : %d", got)
	}
	if _, ok := a.srv.nodeStore.Get("intrus"); ok {
		t.Fatal("l'Agent d'un autre groupe ne doit pas entrer")
	}
}

// Une commande pour un Agent que le groupe a vu sur un autre membre lui est transmise, une seule fois.
func TestCommandIsForwardedToTheMemberHoldingTheAgent(t *testing.T) {
	var calls, forwarded atomic.Int32
	holder := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("X-Gpx-Forwarded") != "" {
			forwarded.Add(1)
		}
		w.WriteHeader(http.StatusAccepted)
	}))
	defer holder.Close()

	b := newStateNode(t, "backup", groupKey, []string{"frontal", "backup"})
	b.srv.wsHub = edgews.NewHub("secret", b.srv.log.Logger())
	b.srv.peers = proxy.NewPeerRegistry()
	b.srv.peers.Replace([]proxy.PeerInfo{{Name: "frontal", Endpoint: holder.URL, Token: "tok"}})
	b.srv.nodeStore.Merge([]edgeagent.NodeInfo{{NodeName: "agent-1", Role: "agent", Status: "online", ConnectedVia: "frontal", LastSeenAt: time.Now()}})

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/agent/agent-1/command", bytes.NewBufferString(`{"action":"rescan"}`))
	req.SetPathValue("name", "agent-1")
	rr := httptest.NewRecorder()
	b.srv.handleAgentCommandRelay(rr, req)
	if rr.Code != http.StatusAccepted || calls.Load() != 1 || forwarded.Load() != 1 {
		t.Fatalf("la commande doit être transmise au membre qui tient l'Agent : status %d, %d appels, %d marqués", rr.Code, calls.Load(), forwarded.Load())
	}

	// Une commande déjà transmise n'est pas retransmise (pas de boucle) : elle tente l'endpoint de l'Agent, ici inconnu.
	req = httptest.NewRequest(http.MethodPost, "/internal/v1/agent/agent-1/command", bytes.NewBufferString(`{"action":"rescan"}`))
	req.SetPathValue("name", "agent-1")
	req.Header.Set("X-Gpx-Forwarded", "1")
	rr = httptest.NewRecorder()
	b.srv.handleAgentCommandRelay(rr, req)
	if calls.Load() != 1 || rr.Code != http.StatusNotFound {
		t.Fatalf("pas de retransmission : %d appels, status %d", calls.Load(), rr.Code)
	}
}
