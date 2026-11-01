// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Remplacer le proxy d'un autre domaine par une config de son propre domaine est refusé : le proxy remplacé compte
// autant que la config reçue.
func TestPutCannotOverwriteAProxyOutsideTheScope(t *testing.T) {
	edge := &fakeEdge{
		prod: map[string]json.RawMessage{
			"p1": json.RawMessage(`{"id":"p1","host":"app.test","type":"http","backends":[{"url":"http://10.0.0.1:80"}]}`),
			"p2": json.RawMessage(`{"id":"p2","host":"secret.autre.io","type":"http","backends":[{"url":"http://10.0.0.2:80"}]}`),
		},
		rev: map[string]json.RawMessage{},
	}
	srv := httptest.NewServer(edge.handler())
	defer srv.Close()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('scoped','s@x.fr','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('t-scoped','equipe test')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('t-scoped','scoped')`,
		`INSERT INTO team_scopes (id, team_id, scope_type, scope_value, access_mode) VALUES ('g1','t-scoped','domain','*.test','write')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint, rbac_role) VALUES ('t1','tok','edge','edge1',?, 'operator')`, srv.URL); err != nil {
		t.Fatal(err)
	}
	h := adminauth.RequireJWT("secret")(&api.ProxiesHandler{DB: db, Log: slog.Default()})
	put := func(id string) *httptest.ResponseRecorder {
		tok, _ := adminauth.SignJWT("scoped", "secret", time.Hour)
		body := `{"config":{"host":"mine.test","type":"http","backends":[{"url":"http://10.0.0.9:80"}]}}`
		req := httptest.NewRequest(http.MethodPut, "/api/v1/proxies/"+id, strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	if rec := put("p2"); rec.Code != http.StatusForbidden {
		t.Fatalf("remplacer le proxy d'un autre domaine : %d %s", rec.Code, rec.Body)
	}
	if !strings.Contains(string(edge.prod["p2"]), "secret.autre.io") {
		t.Fatalf("le proxy d'origine reste intact : %s", edge.prod["p2"])
	}
	if rec := put("p1"); rec.Code != http.StatusOK {
		t.Fatalf("modifier son propre proxy : %d %s", rec.Code, rec.Body)
	}
}
