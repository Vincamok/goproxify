// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"testing"
	"time"
)

func node(name, status, via string, seen time.Time) NodeInfo {
	return NodeInfo{NodeName: name, Role: "agent", Status: status, ConnectedVia: via, LastSeenAt: seen, Endpoint: "http://" + name + ":8001"}
}

// L'Agent qui a basculé vers un autre membre y est vu : l'entrée la plus récente l'emporte, quel que soit le sens.
func TestMergeAdoptsTheMostRecentEntry(t *testing.T) {
	now := time.Now().UTC()
	s := NewNodeStore()
	s.Merge([]NodeInfo{node("ag", "online", "frontal", now.Add(-60*time.Second))})

	if got := s.Merge([]NodeInfo{node("ag", "online", "backup", now)}); got != 1 {
		t.Fatalf("une entrée plus récente est adoptée : %d", got)
	}
	if n, _ := s.Get("ag"); n.ConnectedVia != "backup" {
		t.Fatalf("connected_via = %q", n.ConnectedVia)
	}
	if got := s.Merge([]NodeInfo{node("ag", "online", "frontal", now.Add(-30*time.Second))}); got != 0 {
		t.Fatalf("une entrée plus ancienne est ignorée : %d", got)
	}
	if n, _ := s.Get("ag"); n.ConnectedVia != "backup" {
		t.Fatal("l'entrée plus ancienne ne remplace rien")
	}
}

// Une entrée en attente plus ancienne ne masque pas un Agent en ligne.
func TestMergePendingDoesNotHideAnOnlineAgent(t *testing.T) {
	now := time.Now().UTC()
	s := NewNodeStore()
	s.Merge([]NodeInfo{node("ag", "online", "backup", now)})
	s.Merge([]NodeInfo{node("ag", "pending", "frontal", now.Add(-20*time.Second))})
	if n, _ := s.Get("ag"); n.Status != "online" {
		t.Fatalf("statut = %q", n.Status)
	}
}

// L'état « hors ligne » vient de la date de dernière vue, pas de ce qu'un pair affirme : sans nouvelle vue, l'Agent
// passe hors ligne même s'il était « en ligne » chez le pair.
func TestMergedAgentGoesOfflineWhenNobodySeesItAnymore(t *testing.T) {
	s := NewNodeStore()
	s.Merge([]NodeInfo{node("ag", "online", "frontal", time.Now().UTC().Add(-3*time.Minute))})
	s.MarkOffline(90 * time.Second)
	if n, _ := s.Get("ag"); n.Status != "offline" {
		t.Fatalf("statut = %q, attendu offline", n.Status)
	}
}

func TestMergeKeepsKnownEndpointWhenThePeerDoesNotHaveOne(t *testing.T) {
	now := time.Now().UTC()
	s := NewNodeStore()
	s.Merge([]NodeInfo{node("ag", "online", "frontal", now.Add(-time.Minute))})
	fresher := node("ag", "online", "backup", now)
	fresher.Endpoint = ""
	s.Merge([]NodeInfo{fresher})
	if n, _ := s.Get("ag"); n.Endpoint != "http://ag:8001" || n.ConnectedVia != "backup" {
		t.Fatalf("endpoint conservé, passerelle mise à jour : %+v", n)
	}
}
