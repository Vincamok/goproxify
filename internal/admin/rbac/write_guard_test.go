// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// Même chaîne que adminWrites / operatorWrites dans server.go. EnforcePATScope ne
// s'applique pas aux sessions UI (JWT) : le garde de rôle doit suffire seul.
func TestWriteGuards_JWTAndPAT(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "w.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	must := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t.local','x','user')`)
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('w','w@t.local','x','user')`)
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('a','a@t.local','x','admin')`)
	must(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES ('s1','w','domain','*.example.io','write')`)

	const secret = "test-secret"
	creds := map[string]string{}
	for _, u := range []string{"u", "w", "a"} {
		tok, err := auth.SignJWT(u, secret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		creds["jwt:"+u] = tok
	}
	// Un user ne peut pas détenir certs:write : le scope inscrit sur son PAT reste sans effet.
	pats := map[string]struct {
		user   string
		scopes []string
	}{
		"pat:u":      {"u", []string{rbac.ScopeCertsRead, rbac.ScopeCertsWrite, rbac.ScopeSnippetsWrite}},
		"pat:w":      {"w", []string{rbac.ScopeSnippetsWrite, rbac.ScopeCertsWrite}},
		"pat:a":      {"a", []string{rbac.ScopeCertsWrite, rbac.ScopeSnippetsWrite}},
		"pat:a-read": {"a", []string{rbac.ScopeCertsRead}},
	}
	for name, p := range pats {
		plain := auth.GeneratePAT()
		must(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES (?,?,?,?,?)`,
			name, p.user, name, auth.HashPAT(plain), auth.PATPreview(plain))
		for _, s := range p.scopes {
			must(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES (?,?)`, name, s)
		}
		creds[name] = plain
	}

	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	chain := func(guard func(*sql.DB) func(http.Handler) http.Handler) http.Handler {
		return auth.RequireAuth(secret, db)(rbac.EnforcePATScope(db)(guard(db)(ok)))
	}
	adminWrites := chain(rbac.RequireAdminForWrites)
	operatorWrites := chain(rbac.RequireOperatorForWrites)

	cases := []struct {
		h            http.Handler
		method, path string
		cred         string
		want         int
	}{
		// Admin-only writes, sessions UI.
		{adminWrites, http.MethodGet, "/api/v1/certs", "jwt:u", http.StatusNoContent},
		{adminWrites, http.MethodPost, "/api/v1/certs", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/certs/c1/pull-tokens", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPut, "/api/v1/domains/d1", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/domains/d1/renew", "jwt:w", http.StatusForbidden},
		{adminWrites, http.MethodDelete, "/api/v1/alert-rules/r1", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/alert-channels", "jwt:w", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/alert-events/e1/ack", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/ip-profiles/p1/refresh", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/certs", "jwt:a", http.StatusNoContent},
		{adminWrites, http.MethodDelete, "/api/v1/domains/d1", "jwt:a", http.StatusNoContent},
		// Admin-only writes, PAT.
		{adminWrites, http.MethodGet, "/api/v1/certs", "pat:u", http.StatusNoContent},
		{adminWrites, http.MethodPost, "/api/v1/certs/import", "pat:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/certs/import", "pat:w", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/certs/import", "pat:a-read", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/certs/import", "pat:a", http.StatusNoContent},
		// Snippets : admin ou user avec un grant write.
		{operatorWrites, http.MethodGet, "/api/v1/snippets", "jwt:u", http.StatusNoContent},
		{operatorWrites, http.MethodPost, "/api/v1/snippets", "jwt:u", http.StatusForbidden},
		{operatorWrites, http.MethodPost, "/api/v1/snippets", "pat:u", http.StatusForbidden},
		{operatorWrites, http.MethodPut, "/api/v1/snippets/s1", "jwt:w", http.StatusNoContent},
		{operatorWrites, http.MethodPost, "/api/v1/snippets", "pat:w", http.StatusNoContent},
		{operatorWrites, http.MethodDelete, "/api/v1/snippets/s1", "jwt:a", http.StatusNoContent},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		req.Header.Set("Authorization", "Bearer "+creds[c.cred])
		rec := httptest.NewRecorder()
		c.h.ServeHTTP(rec, req)
		if rec.Code != c.want {
			t.Errorf("%s %s as %s: got %d want %d (%s)", c.method, c.path, c.cred, rec.Code, c.want, rec.Body.String())
		}
	}
}
