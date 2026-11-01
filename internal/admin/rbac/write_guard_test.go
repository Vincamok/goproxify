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
	"github.com/vincamok/goproxify/internal/admin/rbac/rbactest"
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
	grantViaTeam(t, db, "w", "domain", "*.example.io", "write")
	// u lit les certificats (niveau Lecture du service Certificats) : sans accès d'équipe, un compte ne détient aucun scope.
	rbactest.AddAccess(t, db, grantViaTeam(t, db, "u", "domain", "*.example.io", "read"), rbac.TeamAccess{Name: "certs", Levels: map[string]string{"certs": "read", "logs": "read"}})

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
		"pat:a-read": {"a", []string{rbac.ScopeCertsRead, rbac.ScopeLogsRead}},
		"pat:u-logs": {"u", []string{rbac.ScopeLogsRead, rbac.ScopeLogsWrite}},
		"pat:a-logs": {"a", []string{rbac.ScopeLogsWrite}},
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
		// Logs : lecture ouverte ; réglages RGPD et effacement réservés aux admins.
		{adminWrites, http.MethodGet, "/api/v1/logs", "jwt:u", http.StatusNoContent},
		{adminWrites, http.MethodGet, "/api/v1/logs/settings", "pat:a-read", http.StatusNoContent},
		{adminWrites, http.MethodPut, "/api/v1/logs/settings", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodDelete, "/api/v1/logs/by-ip/203.0.113.7", "jwt:w", http.StatusForbidden},
		{adminWrites, http.MethodDelete, "/api/v1/logs/by-user/u", "pat:u-logs", http.StatusForbidden},
		{adminWrites, http.MethodPut, "/api/v1/logs/settings", "pat:a-read", http.StatusForbidden},
		{adminWrites, http.MethodPut, "/api/v1/logs/settings", "pat:a-logs", http.StatusNoContent},
		{adminWrites, http.MethodDelete, "/api/v1/logs/by-ip/203.0.113.7", "jwt:a", http.StatusNoContent},
		{adminWrites, http.MethodPost, "/api/v1/logs/reveal-ip", "jwt:u", http.StatusForbidden},
		{adminWrites, http.MethodPost, "/api/v1/logs/reveal-ip", "pat:a-logs", http.StatusForbidden},
		// Snippets : admin ou user avec un grant write (REST) ; en PAT, administrateur seul.
		{operatorWrites, http.MethodGet, "/api/v1/snippets", "jwt:u", http.StatusNoContent},
		{operatorWrites, http.MethodPost, "/api/v1/snippets", "jwt:u", http.StatusForbidden},
		{operatorWrites, http.MethodPost, "/api/v1/snippets", "pat:u", http.StatusForbidden},
		{operatorWrites, http.MethodPut, "/api/v1/snippets/s1", "jwt:w", http.StatusNoContent},
		// L'écriture des snippets est réservée à la plateforme (ADR 0022, D5) : aucun accès d'équipe ne donne snippets:write.
		{operatorWrites, http.MethodPost, "/api/v1/snippets", "pat:w", http.StatusForbidden},
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

// rbac.Gate refuse à un compte sans accès une lecture qu'il n'a pas le droit de faire, laisse passer l'administrateur et
// range l'appelant dans le contexte pour que le handler filtre.
func TestGateChecksTheCataloguePermission(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "gate.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('reader','r@t','x','user'), ('none','n@t','x','user'), ('boss','b@t','x','admin')`,
		`INSERT INTO teams (id, name) VALUES ('t','t'); INSERT INTO team_members (team_id, user_id) VALUES ('t','reader')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	rbactest.AddAccess(t, db, "t", rbac.TeamAccess{Name: "logs", Levels: map[string]string{"logs": "read"}, Perimeter: rbac.Perimeter{Domain: "*.corp.io"}})

	resolve := func(r *http.Request) (string, bool) {
		switch r.URL.Path {
		case "/logs":
			return "logs:read", true
		case "/certs":
			return "certs:read", true
		}
		return "", false // pas gérée par cette garde
	}
	var seen *rbac.Caller
	next := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = rbac.CallerFrom(r.Context())
		w.WriteHeader(http.StatusNoContent)
	})
	const secret = "gate-secret"
	h := auth.RequireAuth(secret, db)(rbac.Gate(db, resolve)(next))
	call := func(user, path string) int {
		tok, err := auth.SignJWT(user, secret, time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(http.MethodGet, path, nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		user, path string
		want       int
	}{
		{"reader", "/logs", http.StatusNoContent},
		{"reader", "/certs", http.StatusForbidden},
		{"none", "/logs", http.StatusForbidden},
		{"boss", "/certs", http.StatusNoContent},
		{"none", "/autre", http.StatusNoContent},
	} {
		if got := call(c.user, c.path); got != c.want {
			t.Errorf("%s %s : %d, attendu %d", c.user, c.path, got, c.want)
		}
	}
	call("reader", "/logs")
	if seen == nil || seen.UserID != "reader" || seen.IsAdmin() || len(seen.Accesses) != 1 {
		t.Errorf("appelant rangé dans le contexte : %+v", seen)
	}
}

// GateMemberReads : un compte sans aucun accès d'équipe ne lit pas la topologie ; un membre la lit ; les écritures
// passent au handler, qui les juge.
func TestGateMemberReads(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "member.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('member','m@t','x','user'), ('empty','e@t','x','user'), ('lonely','l@t','x','user'), ('boss','b@t','x','admin')`,
		`INSERT INTO teams (id, name) VALUES ('t','t'), ('t0','vide'); INSERT INTO team_members (team_id, user_id) VALUES ('t','member'), ('t0','empty')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	rbactest.AddAccess(t, db, "t", rbac.TeamAccess{Name: "a", Levels: map[string]string{"proxies": "read"}})
	rbactest.AddAccess(t, db, "t0", rbac.TeamAccess{Name: "rien"}) // un accès sans niveau ne donne rien

	const secret = "member-secret"
	h := auth.RequireAuth(secret, db)(rbac.GateMemberReads(db)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })))
	call := func(user, method string) int {
		tok, _ := auth.SignJWT(user, secret, time.Hour)
		req := httptest.NewRequest(method, "/api/v1/nodes", nil)
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Code
	}
	for _, c := range []struct {
		user, method string
		want         int
	}{
		{"member", "GET", http.StatusNoContent},
		{"boss", "GET", http.StatusNoContent},
		{"empty", "GET", http.StatusForbidden},
		{"lonely", "GET", http.StatusForbidden},
		{"lonely", "PATCH", http.StatusNoContent}, // l'écriture est jugée par le handler
	} {
		if got := call(c.user, c.method); got != c.want {
			t.Errorf("%s %s : %d, attendu %d", c.user, c.method, got, c.want)
		}
	}
}
