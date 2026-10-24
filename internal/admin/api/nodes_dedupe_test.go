// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func agentRow(name, status, edge string, seen time.Time) nodeRow {
	return nodeRow{ID: name, NodeName: name, Role: "agent", Status: status, TargetEdge: edge, LastSeenAt: seen}
}

// Les membres d'un groupe HA partagent leur liste d'Agents : un Agent n'apparaît qu'une fois, avec la passerelle qui le
// tient et l'état le plus récent.
func TestDedupeAgentNodesKeepsTheMostRecentlySeen(t *testing.T) {
	now := time.Now()
	rows := []nodeRow{
		agentRow("agent-1", "offline", "frontal", now.Add(-3*time.Minute)),
		agentRow("agent-1", "online", "backup", now),
		agentRow("agent-2", "online", "frontal", now),
		agentRow("agent-2", "online", "backup", now.Add(-10*time.Second)),
	}
	got := dedupeAgentNodes(rows)
	if len(got) != 2 {
		t.Fatalf("une ligne par Agent : %d", len(got))
	}
	byName := map[string]nodeRow{}
	for _, n := range got {
		byName[n.NodeName] = n
	}
	if byName["agent-1"].TargetEdge != "backup" || byName["agent-1"].Status != "online" {
		t.Fatalf("agent-1 : %+v", byName["agent-1"])
	}
	if byName["agent-2"].TargetEdge != "frontal" {
		t.Fatalf("agent-2 : %+v", byName["agent-2"])
	}
}

func TestDedupePrefersOnlineWhenSeenAtTheSameTime(t *testing.T) {
	now := time.Now()
	got := dedupeAgentNodes([]nodeRow{agentRow("a", "offline", "frontal", now), agentRow("a", "online", "backup", now)})
	if len(got) != 1 || got[0].Status != "online" {
		t.Fatalf("%+v", got)
	}
}

// Une passerelle récente rapporte le membre qui a vu l'Agent (connected_via) ; une ancienne n'en dit rien et sa propre
// identité fait foi.
func TestFetchNodesFromEdgeUsesConnectedViaOrTheAnsweringGateway(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode([]map[string]any{
			{"node_name": "agent-1", "status": "online", "connected_via": "backup", "last_seen_at": time.Now()},
			{"node_name": "agent-2", "status": "online", "last_seen_at": time.Now()},
		})
	}))
	defer srv.Close()
	rows := fetchNodesFromEdge(context.Background(), srv.URL, "tok", "frontal")
	if len(rows) != 2 || rows[0].TargetEdge != "backup" || rows[1].TargetEdge != "frontal" {
		t.Fatalf("%+v", rows)
	}
}
