// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"log/slog"
	"net/http"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// La révocation des jetons d'un ancien Admin est réservée aux administrateurs et rend le nombre de passerelles sollicitées.
func TestRevokeStaleAdminTokensEndpoint(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('su','su@x.fr','x','superadmin')`); err != nil {
		t.Fatal(err)
	}
	calls := 0
	h := adminauth.RequireJWT("secret")(&api.NodesHandler{DB: db, Log: slog.Default(),
		RevokeStaleAdminTokens: func(context.Context) int { calls++; return 2 }})

	rec := doAs(h, http.MethodPost, "/api/v1/nodes/revoke-stale-admin-tokens", ``)
	if rec.Code != http.StatusOK || calls != 1 || !jsonContains(rec.Body.String(), `"gateways":2`) {
		t.Fatalf("POST: %d %s (appels %d)", rec.Code, rec.Body.String(), calls)
	}
	if rec := doAs(h, http.MethodGet, "/api/v1/nodes/revoke-stale-admin-tokens", ``); rec.Code == http.StatusOK && calls != 1 {
		t.Fatal("un GET ne révoque rien")
	}
}

func TestRotateTokenEndpoint(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "nodes.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('su','su@x.fr','x','superadmin')`); err != nil {
		t.Fatal(err)
	}
	var asked []string
	h := adminauth.RequireJWT("secret")(&api.NodesHandler{DB: db, Log: slog.Default(),
		RotateEdgeToken: func(_ context.Context, ref string) bool { asked = append(asked, ref); return ref == "frontal" }})

	if rec := doAs(h, http.MethodPost, "/api/v1/nodes/frontal/rotate-token", ``); rec.Code != http.StatusOK || len(asked) != 1 {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	if rec := doAs(h, http.MethodPost, "/api/v1/nodes/inconnue/rotate-token", ``); rec.Code != http.StatusNotFound {
		t.Fatalf("une passerelle inconnue : %d", rec.Code)
	}
}
