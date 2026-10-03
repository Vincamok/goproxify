// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

func newStore(t *testing.T) *AgentHMACStore {
	t.Helper()
	return NewAgentHMACStore(filepath.Join(t.TempDir(), "hmac.json"))
}

// Un Agent approuvé sur A est accepté par B après échange, dans les deux sens.
func TestHMACReplicaConverges(t *testing.T) {
	a, b := newStore(t), newStore(t)
	_ = a.Set("agent-1", "hmac-a")
	time.Sleep(time.Millisecond)
	_ = b.Set("agent-2", "hmac-b")

	if _, _, err := b.Merge(a.Export()); err != nil {
		t.Fatal(err)
	}
	if _, _, err := a.Merge(b.Export()); err != nil {
		t.Fatal(err)
	}
	for _, s := range []*AgentHMACStore{a, b} {
		if v, _ := s.Get("agent-1"); v != "hmac-a" {
			t.Fatalf("agent-1 = %q", v)
		}
		if v, _ := s.Get("agent-2"); v != "hmac-b" {
			t.Fatalf("agent-2 = %q", v)
		}
	}
}

// La rotation d'un HMAC sur un membre se propage : l'Agent, qui a le dernier, est accepté partout.
func TestHMACReplicaRotationWins(t *testing.T) {
	a, b := newStore(t), newStore(t)
	_ = a.Set("agent-1", "v1")
	_, _, _ = b.Merge(a.Export())
	time.Sleep(time.Millisecond)
	_ = a.Set("agent-1", "v2")
	_, _, _ = b.Merge(a.Export())
	if v, _ := b.Get("agent-1"); v != "v2" {
		t.Fatalf("rotation non répliquée : %q", v)
	}
	// Un état ancien rejoué ne revient pas en arrière.
	old := HMACReplica{V: 1, Data: map[string]string{"agent-1": "v1"}, Stamps: map[string]int64{"agent-1": 1}}
	if changed, _, _ := b.Merge(old); changed {
		t.Fatal("un état plus ancien ne doit rien changer")
	}
	if v, _ := b.Get("agent-1"); v != "v2" {
		t.Fatalf("retour arrière : %q", v)
	}
}

// Une révocation sur A retire l'Agent sur B, et un pair qui n'a pas vu la révocation ne le ressuscite pas.
func TestHMACReplicaRevocationPropagates(t *testing.T) {
	a, b := newStore(t), newStore(t)
	_ = a.Set("agent-1", "v1")
	_, _, _ = b.Merge(a.Export())
	stale := b.Export() // B garde l'ancien état dans une copie

	time.Sleep(time.Millisecond)
	_ = a.Delete("agent-1")
	_, removed, _ := b.Merge(a.Export())
	if len(removed) != 1 || removed[0] != "agent-1" {
		t.Fatalf("agents retirés : %v", removed)
	}
	if _, ok := b.Get("agent-1"); ok {
		t.Fatal("l'Agent révoqué est encore accepté")
	}
	if _, _, err := a.Merge(stale); err != nil {
		t.Fatal(err)
	}
	if _, ok := a.Get("agent-1"); ok {
		t.Fatal("l'Agent révoqué a été ressuscité par un état périmé")
	}
}

// Une approbation postérieure à la révocation redonne l'accès.
func TestHMACReapprovalAfterRevocation(t *testing.T) {
	a, b := newStore(t), newStore(t)
	_ = a.Set("agent-1", "v1")
	time.Sleep(time.Millisecond)
	_ = a.Delete("agent-1")
	time.Sleep(time.Millisecond)
	_ = a.Set("agent-1", "v2")
	_, _, _ = b.Merge(a.Export())
	if v, _ := b.Get("agent-1"); v != "v2" {
		t.Fatalf("ré-approbation non répliquée : %q", v)
	}
}

func TestHMACMergeDoesNotNotify(t *testing.T) {
	a, b := newStore(t), newStore(t)
	var n atomic.Int32
	b.SetOnChange(func() { n.Add(1) })
	_ = a.Set("agent-1", "v1")
	_, _, _ = b.Merge(a.Export())
	time.Sleep(20 * time.Millisecond)
	if n.Load() != 0 {
		t.Fatal("une fusion ne doit pas redéclencher l'envoi (boucle d'échanges)")
	}
	_ = b.Set("agent-2", "v")
	time.Sleep(20 * time.Millisecond)
	if n.Load() != 1 {
		t.Fatalf("une modification locale doit notifier : %d", n.Load())
	}
}

// Un fichier écrit avant la réplication (simple table id → hmac) est relu et survit à une fusion.
func TestHMACStoreReadsLegacyFile(t *testing.T) {
	path := filepath.Join(t.TempDir(), "hmac.json")
	if err := os.WriteFile(path, []byte(`{"agent-1":"legacy"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	s := NewAgentHMACStore(path)
	if v, _ := s.Get("agent-1"); v != "legacy" {
		t.Fatalf("ancien format : %q", v)
	}
	_, _, _ = s.Merge(HMACReplica{V: 1, Data: map[string]string{"agent-1": "autre"}, Stamps: map[string]int64{"agent-1": 1}})
	if v, _ := NewAgentHMACStore(path).Get("agent-1"); v != "legacy" {
		t.Fatalf("un état répliqué plus ancien a écrasé le HMAC local : %q", v)
	}
}

func TestHMACReplicaSealOpen(t *testing.T) {
	r := HMACReplica{V: 1, Data: map[string]string{"agent-1": "secret-hmac"}, Stamps: map[string]int64{"agent-1": 5}}
	sealed, err := SealHMACReplica(r, "cle-groupe")
	if err != nil {
		t.Fatal(err)
	}
	if string(sealed) == "" || containsBytes(sealed, "secret-hmac") {
		t.Fatal("HMAC en clair dans l'état chiffré")
	}
	got, err := OpenHMACReplica(sealed, "cle-groupe")
	if err != nil || got.Data["agent-1"] != "secret-hmac" {
		t.Fatalf("ouverture : %+v %v", got, err)
	}
	if _, err := OpenHMACReplica(sealed, "autre-groupe"); err == nil {
		t.Fatal("une autre clé de groupe ne doit pas déchiffrer")
	}
	if _, err := SealHMACReplica(r, ""); err == nil {
		t.Fatal("sans clé de groupe, pas de chiffrement")
	}
}

func containsBytes(b []byte, s string) bool {
	for i := 0; i+len(s) <= len(b); i++ {
		if string(b[i:i+len(s)]) == s {
			return true
		}
	}
	return false
}
