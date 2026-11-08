// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/archstore"
)

func TestUserTokenAudience(t *testing.T) {
	db := openSQLDatesDB(t)
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1', 'a@example.com', 'x', 'admin')`); err != nil {
		t.Fatal(err)
	}
	jwt, err := adminauth.SignJWT("u1", "secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	h := adminauth.RequireJWT("secret")(&UserTokensHandler{DB: db, Log: slog.Default()})
	post := func(body map[string]any) *httptest.ResponseRecorder {
		b, _ := json.Marshal(body)
		req := httptest.NewRequest(http.MethodPost, "/api/v1/me/tokens", bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+jwt)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	cases := []struct {
		name string
		body map[string]any
		code int
		want string
	}{
		{"sans usage : les deux", map[string]any{"label": "a", "scopes": []string{"certs:read"}}, http.StatusCreated, "both"},
		{"API", map[string]any{"label": "b", "audience": "api", "scopes": []string{"gdpr:export"}}, http.StatusCreated, "api"},
		{"MCP", map[string]any{"label": "c", "audience": "mcp", "scopes": []string{"certs:read"}}, http.StatusCreated, "mcp"},
		{"MCP avec un scope sans outil MCP", map[string]any{"label": "d", "audience": "mcp", "scopes": []string{"gdpr:export"}}, http.StatusBadRequest, ""},
		{"usage inconnu", map[string]any{"label": "e", "audience": "ftp", "scopes": []string{"certs:read"}}, http.StatusBadRequest, ""},
	}
	for _, c := range cases {
		rec := post(c.body)
		if rec.Code != c.code {
			t.Fatalf("%s : status %d %s, attendu %d", c.name, rec.Code, rec.Body, c.code)
		}
		if c.want == "" {
			continue
		}
		var out struct {
			Audience string `json:"audience"`
		}
		json.Unmarshal(rec.Body.Bytes(), &out) //nolint:errcheck
		if out.Audience != c.want {
			t.Errorf("%s : audience %q, attendu %q", c.name, out.Audience, c.want)
		}
	}

	req := httptest.NewRequest(http.MethodGet, "/api/v1/me/tokens", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var list []struct {
		Label    string `json:"label"`
		Audience string `json:"audience"`
	}
	json.Unmarshal(rec.Body.Bytes(), &list) //nolint:errcheck
	got := map[string]string{}
	for _, tk := range list {
		got[tk.Label] = tk.Audience
	}
	if len(got) != 3 || got["a"] != "both" || got["b"] != "api" || got["c"] != "mcp" {
		t.Errorf("liste : %v", got)
	}

	// L'usage survit à users.yaml : sans lui, un token MCP restauré deviendrait un token API aussi.
	dir := t.TempDir()
	if err := archstore.NewUserStore(dir).SyncFromDB(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	restored := openSQLDatesDB(t)
	if err := archstore.NewUserStore(dir).LoadIntoDB(context.Background(), restored); err != nil {
		t.Fatal(err)
	}
	var aud string
	if err := restored.QueryRow(`SELECT audience FROM user_api_tokens WHERE label='c'`).Scan(&aud); err != nil || aud != "mcp" {
		t.Errorf("usage restauré depuis users.yaml : %q (%v), attendu mcp", aud, err)
	}
}
