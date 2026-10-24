// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/edgeset"
	"github.com/vincamok/goproxify/internal/config"
)

// Pendant une rotation de la clé des Agents, un Agent dont la clé courante n'est pas encore connue de sa passerelle
// s'appaire avec la précédente au lieu d'échouer.
func TestPairWithEdgeFallsBackToThePreviousKey(t *testing.T) {
	var seen []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var req struct {
			Secret string `json:"secret"`
		}
		_ = json.NewDecoder(r.Body).Decode(&req)
		seen = append(seen, req.Secret)
		if req.Secret != "cle-ancienne" {
			http.Error(w, "secret invalide", http.StatusForbidden)
			return
		}
		w.WriteHeader(http.StatusCreated)
		_, _ = w.Write([]byte(`{"token":"jeton-agent"}`))
	}))
	t.Cleanup(srv.Close)

	t.Setenv("GPX_PAIRING_SECRET", "")
	t.Setenv("GPX_AGENT_PAIRING_KEY", "cle-nouvelle")
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "cle-ancienne")
	a := &Agent{
		cfg:         &config.AgentConfig{},
		log:         slog.Default(),
		edges:       edgeset.New(srv.URL, ""),
		internalAPI: &internalAPI{},
	}
	a.cfg.ControlPlane.EdgeEndpoint = srv.URL

	tok, err := a.pairWithEdge(context.Background())
	if err != nil || tok != "jeton-agent" {
		t.Fatalf("appairage : %q %v", tok, err)
	}
	if len(seen) != 2 || seen[0] != "cle-nouvelle" || seen[1] != "cle-ancienne" {
		t.Fatalf("la clé courante d'abord, la précédente ensuite : %v", seen)
	}

	// Aucune des deux clés n'est connue : l'appairage échoue, sans boucler.
	seen = nil
	t.Setenv("GPX_AGENT_PAIRING_KEY_PREVIOUS", "cle-inconnue")
	if _, err := a.pairWithEdge(context.Background()); err == nil || len(seen) != 2 {
		t.Fatalf("refus attendu après deux essais : err=%v essais=%v", err, seen)
	}
}
