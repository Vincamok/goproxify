// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"testing"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestMergeCardsKeepsWhatIsAlreadyDeclared(t *testing.T) {
	s := New(t.TempDir())
	if err := s.Upsert(NodeEntry{ID: "n1", Role: "edge", Name: "frontal", Endpoint: "https://local:1"}); err != nil {
		t.Fatal(err)
	}
	rep, err := s.MergeCards([]edgews.GroupCard{{
		Group: "ha-1", Version: 2,
		Members: []edgews.CardMember{{ID: "n1", Name: "frontal", Endpoint: "https://carte:2"}, {ID: "n9", Name: "renomme-n9", Endpoint: "https://b:3"}, {ID: "n3", Name: "backup"}},
		Domains: []edgews.CardDomain{{ID: "d1", Domain: "app.example.fr", EdgeID: "n1", CertMethod: "http"}},
	}})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Nodes != 2 || rep.Joined != 1 || rep.Domains != 1 || rep.Skipped != 0 {
		t.Fatalf("rapport : %+v", rep)
	}
	arch, _ := s.Get()
	for _, n := range arch.Nodes {
		if n.ID == "n1" && n.Endpoint != "https://local:1" {
			t.Fatalf("le nœud connu garde son endpoint : %+v", n)
		}
	}
	if g := s.GroupMembers("ha-1"); len(g) != 3 {
		t.Fatalf("le nœud connu sans config rejoint le groupe avec les deux autres : %+v", g)
	}

	// Rejouée, la reconstitution n'ajoute plus rien et ne touche pas une config déjà déclarée.
	again, err := s.MergeCards([]edgews.GroupCard{{Group: "ha-2", Version: 1, Members: []edgews.CardMember{{ID: "n1", Name: "frontal"}}}})
	if err != nil {
		t.Fatal(err)
	}
	if again.Nodes != 0 || again.Joined != 0 || again.Skipped != 1 || len(s.GroupMembers("ha-2")) != 0 || len(s.GroupMembers("ha-1")) != 3 {
		t.Fatalf("rejeu : %+v", again)
	}

	// Une fiche plus ancienne ne fait pas redescendre la version.
	if _, err := s.MergeCards([]edgews.GroupCard{{Group: "ha-1", Version: 1}}); err != nil {
		t.Fatal(err)
	}
	if v, _ := s.GroupCardVersion("ha-1"); v != 2 {
		t.Fatalf("version : %d", v)
	}
}
