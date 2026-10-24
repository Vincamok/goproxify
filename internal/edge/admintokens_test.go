// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func adminTokenServer(t *testing.T) *Server {
	t.Helper()
	ts, err := edgetokens.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	return &Server{tokenStore: ts, cfg: &config.EdgeConfig{}, log: edgelog.New("error", "text", "")}
}

func pushToEdge(t *testing.T, s *Server, typ string, v any) error {
	t.Helper()
	b, _ := json.Marshal(v)
	return s.applyAdminMessage("admin", edgews.Message{Type: typ, Payload: b})
}

// Un Admin remplacé laisse son jeton valable sur la passerelle ; le nouvel Admin le fait révoquer sans se couper l'accès,
// et les jetons d'amorçage de la configuration ne bougent pas.
func TestStaleAdminTokensAreRevokedOnRequest(t *testing.T) {
	s := adminTokenServer(t)
	_ = s.tokenStore.EnsureToken("admin-edge-1", "gpx_amorcage", edgetokens.RoleAdmin)
	if err := pushToEdge(t, s, edgews.TypeAdminToken, edgews.AdminTokenPayload{Token: "gpx_ancien_admin"}); err != nil {
		t.Fatal(err)
	}
	if err := pushToEdge(t, s, edgews.TypeAdminToken, edgews.AdminTokenPayload{Token: "gpx_nouvel_admin"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.tokenStore.RoleOf("gpx_ancien_admin"); !ok {
		t.Fatal("avant la demande, l'ancien jeton reste valable")
	}

	if err := pushToEdge(t, s, edgews.TypeRevokeStaleAdminTokens, edgews.AdminTokenPayload{Token: "gpx_nouvel_admin"}); err != nil {
		t.Fatal(err)
	}
	for raw, want := range map[string]bool{"gpx_ancien_admin": false, "gpx_nouvel_admin": true, "gpx_amorcage": true} {
		if _, ok, _ := s.tokenStore.RoleOf(raw); ok != want {
			t.Errorf("%s : valide=%v, attendu %v", raw, ok, want)
		}
	}
}

// Le jeton à garder est enregistré d'abord : la demande ne coupe jamais l'accès de l'Admin qui la fait. Sans jeton, elle est
// refusée et rien n'est révoqué.
func TestRevokeStaleAdminTokensNeverLocksOutTheCaller(t *testing.T) {
	s := adminTokenServer(t)
	_ = pushToEdge(t, s, edgews.TypeAdminToken, edgews.AdminTokenPayload{Token: "gpx_ancien_admin"})

	if err := pushToEdge(t, s, edgews.TypeRevokeStaleAdminTokens, edgews.AdminTokenPayload{}); err == nil {
		t.Fatal("une demande sans jeton à garder est refusée")
	}
	if _, ok, _ := s.tokenStore.RoleOf("gpx_ancien_admin"); !ok {
		t.Fatal("rien n'est révoqué sans jeton à garder")
	}
	if err := pushToEdge(t, s, edgews.TypeRevokeStaleAdminTokens, edgews.AdminTokenPayload{Token: "gpx_jamais_vu"}); err != nil {
		t.Fatal(err)
	}
	if _, ok, _ := s.tokenStore.RoleOf("gpx_jamais_vu"); !ok {
		t.Fatal("le jeton à garder est enregistré par la demande")
	}
	if _, ok, _ := s.tokenStore.RoleOf("gpx_ancien_admin"); ok {
		t.Fatal("l'ancien jeton est révoqué")
	}
}
