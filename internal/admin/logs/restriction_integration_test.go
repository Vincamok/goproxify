// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Une restriction d'hôtes borne la recherche, les facettes et l'histogramme sur une vraie base : les lignes d'un autre
// hôte, et les événements de processus sans hôte, ne sortent pas.
func TestRestrictionBoundsSearchFacetsAndHistogram(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	s := New(db)
	s.Write(Entry{NodeName: "e1", Domain: "a.corp.io", Status: 200, Message: "a1"})
	s.Write(Entry{NodeName: "e1", Domain: "a.corp.io", Status: 500, Message: "a2"})
	s.Write(Entry{NodeName: "e1", Domain: "b.corp.io", Status: 200, Message: "b1"})
	s.Write(Entry{NodeName: "e1", Domain: "x.eu.io", Status: 200, Message: "eu1"})
	s.Write(Entry{NodeName: "e1", Component: "edge", Status: 0, Message: "processus"})

	count := func(r *Restriction) int {
		entries, _, err := s.Search(SearchParams{Restrict: r, PageSize: 100})
		if err != nil {
			t.Fatal(err)
		}
		return len(entries)
	}
	if got := count(nil); got != 5 {
		t.Fatalf("sans restriction : %d", got)
	}
	if got := count(&Restriction{Hosts: []string{"a.corp.io"}}); got != 2 {
		t.Errorf("un hôte : %d, attendu 2", got)
	}
	if got := count(&Restriction{Hosts: []string{"a.corp.io"}, Patterns: []string{"*.eu.io"}}); got != 3 {
		t.Errorf("un hôte et un motif : %d, attendu 3", got)
	}
	if got := count(&Restriction{Patterns: []string{"?*"}}); got != 4 {
		t.Errorf("tous les hôtes sans les événements de processus : %d, attendu 4", got)
	}
	if got := count(&Restriction{Patterns: []string{"?*"}, System: true}); got != 5 {
		t.Errorf("avec les logs système : %d, attendu 5", got)
	}
	if got := count(&Restriction{}); got != 0 {
		t.Errorf("restriction vide : %d, attendu 0", got)
	}

	facets, err := s.Facets(SearchParams{Restrict: &Restriction{Hosts: []string{"b.corp.io"}}}, []string{"domain"})
	if err != nil {
		t.Fatal(err)
	}
	if b, ok := facets["domain"]; !ok || len(b) != 1 || b[0].Value != "b.corp.io" {
		t.Errorf("facettes restreintes : %+v", facets)
	}
}
