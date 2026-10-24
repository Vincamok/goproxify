// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package statepub

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
)

func TestGenerationNeverGoesBackAcrossARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "gen")
	p := New("ag", path)
	var last int64
	for i := 0; i < 50; i++ {
		g := p.next()
		if g <= last {
			t.Fatalf("génération %d après %d", g, last)
		}
		last = g
	}
	// Un redémarrage dont l'horloge a reculé repart au-dessus de la dernière génération envoyée.
	restarted := New("ag", path)
	if g := restarted.next(); g <= last {
		t.Fatalf("après redémarrage : %d, attendu au-dessus de %d", g, last)
	}
}

func TestPutOutcomes(t *testing.T) {
	cases := map[int]Result{
		http.StatusOK:                  Sent,
		http.StatusConflict:            Sent,
		http.StatusNotFound:            Unsupported,
		http.StatusMethodNotAllowed:    Unsupported,
		http.StatusBadRequest:          Failed,
		http.StatusInternalServerError: Failed,
	}
	for status, want := range cases {
		var got map[string]any
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.Method != http.MethodPut || r.URL.Path != Path || r.Header.Get("Authorization") != "Bearer tok" {
				t.Errorf("requête inattendue : %s %s %q", r.Method, r.URL.Path, r.Header.Get("Authorization"))
			}
			_ = json.NewDecoder(r.Body).Decode(&got)
			w.WriteHeader(status)
		}))
		res, err := New("ag", "").Put(t.Context(), srv.URL+"/", "tok", "docker", "", nil)
		srv.Close()
		if res != want {
			t.Errorf("statut %d : %v, attendu %v (err %v)", status, res, want, err)
		}
		if got["agent_name"] != "ag" || got["source"] != "docker" || got["generation"] == nil {
			t.Errorf("statut %d : corps %v", status, got)
		}
		if routes, ok := got["routes"].([]any); !ok || len(routes) != 0 {
			t.Errorf("un état vide doit partir en liste vide, pas en null : %v", got["routes"])
		}
	}
}
