// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeset

import (
	"path/filepath"
	"testing"
)

func TestRotateWithoutPeersStaysPut(t *testing.T) {
	s := New("http://edge-a:8000/", "")
	if s.Current() != "http://edge-a:8000" {
		t.Fatalf("courante : %q", s.Current())
	}
	if ep, changed := s.Rotate(); changed || ep != "http://edge-a:8000" {
		t.Fatalf("sans autre membre, pas de bascule : %q %v", ep, changed)
	}
}

func TestRotateCyclesThroughGroup(t *testing.T) {
	s := New("http://edge-a:8000", "")
	s.Update([]string{"http://edge-b:8000", "http://edge-c:8000"})
	var seq []string
	for i := 0; i < 4; i++ {
		ep, changed := s.Rotate()
		if !changed {
			t.Fatal("bascule attendue")
		}
		seq = append(seq, ep)
	}
	want := []string{"http://edge-b:8000", "http://edge-c:8000", "http://edge-a:8000", "http://edge-b:8000"}
	for i := range want {
		if seq[i] != want[i] {
			t.Fatalf("séquence %v, attendu %v", seq, want)
		}
	}
}

// Mettre à jour la liste ne fait pas changer de passerelle tant que la courante y figure.
func TestUpdateKeepsCurrent(t *testing.T) {
	s := New("http://edge-a:8000", "")
	s.Update([]string{"http://edge-b:8000"})
	s.Rotate() // edge-b
	s.Update([]string{"http://edge-c:8000", "http://edge-b:8000"})
	if s.Current() != "http://edge-b:8000" {
		t.Fatalf("la courante a changé : %q", s.Current())
	}
}

// La passerelle configurée n'est pas dupliquée et une liste vide n'efface rien.
func TestUpdateDedupesAndIgnoresEmpty(t *testing.T) {
	s := New("http://edge-a:8000", "")
	s.Update([]string{"http://edge-a:8000/", "http://edge-b:8000", "http://edge-b:8000", ""})
	if s.Len() != 2 {
		t.Fatalf("doublons : %d", s.Len())
	}
	s.Update(nil)
	if s.Len() != 2 {
		t.Fatalf("une liste vide a effacé le groupe : %d", s.Len())
	}
}

// Un Agent redémarré pendant la panne de sa passerelle connaît encore les autres membres.
func TestPersistedAcrossRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent-edges.json")
	s := New("http://edge-a:8000", path)
	s.Update([]string{"http://edge-b:8000"})

	restarted := New("http://edge-a:8000", path)
	if restarted.Len() != 2 {
		t.Fatalf("membres perdus : %d", restarted.Len())
	}
	if ep, _ := restarted.Rotate(); ep != "http://edge-b:8000" {
		t.Fatalf("bascule après redémarrage : %q", ep)
	}
	// La passerelle de la config reste en tête, même si le fichier la désigne autrement.
	if New("http://edge-z:8000", path).Current() != "http://edge-z:8000" {
		t.Fatal("la passerelle configurée doit rester la première")
	}
}

// La passerelle annonce les autres membres, pas elle-même : sur le membre B (la configurée A étant
// tombée), l'annonce [A, C] ne doit pas ramener l'Agent vers A.
func TestUpdateFromFailoverEdgeKeepsCurrent(t *testing.T) {
	s := New("http://edge-a:8000", "")
	s.Update([]string{"http://edge-b:8000"})
	if ep, _ := s.Rotate(); ep != "http://edge-b:8000" {
		t.Fatalf("bascule : %q", ep)
	}
	s.Update([]string{"http://edge-a:8000", "http://edge-c:8000"}) // annonce faite par edge-b
	if s.Current() != "http://edge-b:8000" {
		t.Fatalf("l'annonce de edge-b a ramené l'Agent vers %q", s.Current())
	}
	if s.Len() != 3 {
		t.Fatalf("membres connus : %d", s.Len())
	}
}
