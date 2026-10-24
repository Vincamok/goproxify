// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"fmt"
	"testing"
	"time"
)

// Lire les seuls événements de sécurité page par page, de fichier en fichier, rend chacun une fois et amène le
// curseur à la fin de la base, sans relire les lignes ordinaires écartées.
func TestReadSecurityAfterPagesThroughFilesAndAdvancesPastOrdinaryRows(t *testing.T) {
	s := openTest(t)
	base := at("2026-10-12T12:00:00Z") // trois semaines
	want := map[string]bool{}
	for i := 0; i < 90; i++ {
		e := access(base.Add(time.Duration(i)*8*time.Hour), "198.51.100.1")
		e.Path = fmt.Sprintf("/p/%03d", i)
		e.WAFMatches, e.ThreatSignal = nil, ""
		switch {
		case i%11 == 3:
			e.WAFMatches = []string{"sqli"}
		case i%17 == 5:
			e.ThreatSignal = "scan"
		}
		if e.WAFMatches != nil || e.ThreatSignal != "" {
			want[e.Path] = true
		}
		s.Add(KindAccess, e)
	}
	s.Flush()

	var got []string
	pos, scans := int64(0), 0
	for ; scans < 100; scans++ {
		rows, through, err := s.ReadSecurityAfter(KindAccess, pos, 4)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range rows {
			got = append(got, r.Path)
		}
		if through < pos {
			t.Fatalf("through recule : %d < %d", through, pos)
		}
		if len(rows) < 4 {
			pos = through
			break
		}
		pos = through
	}
	if len(got) != len(want) {
		t.Fatalf("%d événements lus, attendu %d", len(got), len(want))
	}
	for _, p := range got {
		if !want[p] {
			t.Errorf("ligne ordinaire lue : %s", p)
		}
	}
	if pos != s.LastID(KindAccess) {
		t.Errorf("le curseur est à %d, la fin de la base à %d", pos, s.LastID(KindAccess))
	}
	// Plus rien à lire : une lecture suivante ne rend rien et ne bouge pas.
	rows, through, err := s.ReadSecurityAfter(KindAccess, pos, 4)
	if err != nil || len(rows) != 0 || through != pos {
		t.Errorf("relecture : %d lignes, through=%d (attendu %d), %v", len(rows), through, pos, err)
	}
	// Des lignes ordinaires arrivent : le curseur avance sans rien rendre.
	plain := access(base.Add(1000*time.Hour), "198.51.100.1")
	plain.WAFMatches, plain.ThreatSignal = nil, ""
	s.Add(KindAccess, plain)
	s.Flush()
	rows, through, err = s.ReadSecurityAfter(KindAccess, pos, 4)
	if err != nil || len(rows) != 0 || through <= pos {
		t.Errorf("après des lignes ordinaires : %d lignes, through=%d (position %d), %v", len(rows), through, pos, err)
	}
}

func TestLastIDOfAnEmptyStoreIsZero(t *testing.T) {
	s := openTest(t)
	if s.LastID(KindAccess) != 0 {
		t.Error("une base vide n'a pas de dernière ligne")
	}
}
