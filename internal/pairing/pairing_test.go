// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package pairing

import "testing"

func TestAgentKeyIsStableDistinctAndOneWay(t *testing.T) {
	root := "le-secret-racine-0123456789"
	k := AgentKey(root)
	if k == "" || k == root || len(k) != 64 {
		t.Fatalf("clé dérivée invalide : %q", k)
	}
	if k != AgentKey(root) {
		t.Fatal("la dérivation doit être stable")
	}
	if AgentKey(root+"x") == k {
		t.Fatal("deux secrets distincts donnent la même clé")
	}
	if AgentKey("") != "" {
		t.Fatal("un secret vide ne dérive rien")
	}
}

func TestServerAcceptsAgentKeyAndOptionallyRoot(t *testing.T) {
	root := "le-secret-racine-0123456789"
	if ok, viaRoot := ServerAcceptsAgent(root, AgentKey(root)); !ok || viaRoot {
		t.Fatalf("la clé dérivée doit être acceptée sans passer par la racine : ok=%v viaRoot=%v", ok, viaRoot)
	}
	if ok, viaRoot := ServerAcceptsAgent(root, root); !ok || !viaRoot {
		t.Fatalf("le secret racine reste accepté (migration) : ok=%v viaRoot=%v", ok, viaRoot)
	}
	t.Setenv("GPX_AGENT_PAIRING_ROOT", "false")
	if ok, _ := ServerAcceptsAgent(root, root); ok {
		t.Fatal("GPX_AGENT_PAIRING_ROOT=false doit refuser le secret racine d'un Agent")
	}
	if ok, _ := ServerAcceptsAgent(root, AgentKey(root)); !ok {
		t.Fatal("la clé dérivée doit rester acceptée")
	}
	if ok, _ := ServerAcceptsAgent(root, ""); ok {
		t.Fatal("un secret vide ne doit jamais être accepté")
	}
	if ok, _ := ServerAcceptsAgent("", ""); ok {
		t.Fatal("un serveur sans secret n'accepte rien")
	}
}

func TestAgentAcceptsDerivedAndOwnCredential(t *testing.T) {
	root := "le-secret-racine-0123456789"
	key := AgentKey(root)
	legacy := AgentAccepts(root) // Agent qui détient encore la racine
	if legacy[0] != root || legacy[1] != key {
		t.Fatalf("Agent historique : %v", legacy)
	}
	modern := AgentAccepts(key)
	if modern[0] != key {
		t.Fatalf("Agent migré : %v", modern)
	}
}
