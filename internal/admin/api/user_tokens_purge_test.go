// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// Un token révoqué ou expiré se supprime pour de bon ; un token actif ou celui d'un autre compte, non.
func TestUserTokenPurge(t *testing.T) {
	db := openSQLDatesDB(t)
	for _, u := range []string{"u1", "u2"} {
		if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, 'x', 'admin')`, u, u+"@example.com"); err != nil {
			t.Fatal(err)
		}
	}
	past := sqltime.Format(time.Now().Add(-time.Hour))
	for _, r := range []struct {
		id, user string
		revoked  int
		expires  any
	}{
		{"active", "u1", 0, nil},
		{"revoked", "u1", 1, nil},
		{"expired", "u1", 0, past},
		{"other", "u2", 1, nil},
	} {
		if _, err := db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix, revoked, expires_at) VALUES (?, ?, ?, ?, 'p', ?, ?)`,
			r.id, r.user, r.id, "h-"+r.id, r.revoked, r.expires); err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES (?, 'certs:read')`, r.id); err != nil {
			t.Fatal(err)
		}
	}
	jwt, err := adminauth.SignJWT("u1", "secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := adminauth.RequireJWT("secret")(&UserTokensHandler{DB: db, Log: slog.Default()})
	del := func(path string) int {
		req := httptest.NewRequest(http.MethodDelete, path, nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}

	if got := del("/api/v1/me/tokens/active?purge=1"); got != http.StatusConflict {
		t.Errorf("suppression d'un token actif : %d, attendu 409", got)
	}
	if got := del("/api/v1/me/tokens/other?purge=1"); got != http.StatusNotFound {
		t.Errorf("suppression du token d'un autre compte : %d, attendu 404", got)
	}
	for _, id := range []string{"revoked", "expired"} {
		if got := del("/api/v1/me/tokens/" + id + "?purge=1"); got != http.StatusNoContent {
			t.Errorf("suppression de %s : %d, attendu 204", id, got)
		}
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM user_api_tokens WHERE id IN ('revoked','expired')`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Errorf("%d token(s) supprimé(s) encore présent(s)", n)
	}
	db.QueryRow(`SELECT COUNT(*) FROM user_api_token_scopes WHERE token_id IN ('revoked','expired')`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Errorf("%d scope(s) orphelin(s)", n)
	}
	db.QueryRow(`SELECT COUNT(*) FROM user_api_tokens WHERE id IN ('active','other')`).Scan(&n) //nolint:errcheck
	if n != 2 {
		t.Errorf("les tokens actif et d'un autre compte doivent rester : %d sur 2", n)
	}

	// Sans ?purge=1, DELETE révoque toujours : un token actif devient révoqué, il n'est pas supprimé.
	if got := del("/api/v1/me/tokens/active"); got != http.StatusNoContent {
		t.Fatalf("révocation : %d", got)
	}
	var revoked int
	db.QueryRow(`SELECT revoked FROM user_api_tokens WHERE id='active'`).Scan(&revoked) //nolint:errcheck
	if revoked != 1 {
		t.Errorf("le token actif aurait dû être révoqué, pas supprimé (revoked=%d)", revoked)
	}
}
