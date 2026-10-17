// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"context"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"
)

// Une étape de sécurité travaille sur une copie de la requête (WithContext) : ce qu'elle signale doit
// quand même arriver dans l'entrée du journal, qui n'a que la requête d'origine.
func TestAccessLoggerCollectsNotesFromDerivedRequests(t *testing.T) {
	al := NewAccessLogger("")
	got := make(chan ShipEntry, 4)
	al.SetForwarder(func(batch []ShipEntry) {
		for _, e := range batch {
			got <- e
		}
	})
	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		r = r.WithContext(context.WithValue(r.Context(), struct{}{}, 1))
		NoteWAF(r.Context(), "xss", "coraza", "xss", "")
		NoteThreat(r.Context(), "threat: ua")
		w.WriteHeader(http.StatusForbidden)
	}))

	req := httptest.NewRequest(http.MethodGet, "https://app.example.com/x", nil)
	req.Host = "app.example.com"
	req.RemoteAddr = "203.0.113.42:51234"
	h.ServeHTTP(httptest.NewRecorder(), req)

	select {
	case e := <-got:
		if !slices.Equal(e.WAFMatches, []string{"xss", "coraza"}) {
			t.Errorf("waf_matches=%v, attendu [xss coraza] (sans doublon ni vide)", e.WAFMatches)
		}
		if e.ThreatSignal != "threat: ua" {
			t.Errorf("threat_signal=%q", e.ThreatSignal)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("aucune entrée expédiée")
	}
}

func TestNoteWithoutAccessLoggerIsIgnored(t *testing.T) {
	ctx := context.Background()
	NoteWAF(ctx, "xss")
	NoteThreat(ctx, "threat: ua")
}
