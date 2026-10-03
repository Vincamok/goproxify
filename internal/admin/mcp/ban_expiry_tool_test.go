// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"database/sql"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestBanToolsValidateExpiresAt(t *testing.T) {
	h := setupMCPDB(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	tools := map[string]func(args map[string]any) (any, error){
		"create_security_ban": func(args map[string]any) (any, error) { return h.toolCreateSecurityBan(r, args) },
		"ban_ip":              func(args map[string]any) (any, error) { return h.toolBanIP(r, args) },
	}
	for name, call := range tools {
		if _, err := call(map[string]any{"ip": "203.0.113.40", "expires_at": "dans une heure"}); err == nil {
			t.Errorf("%s : expires_at illisible accepté", name)
		}
		res, err := call(map[string]any{"ip": "203.0.113.41", "expires_at": "2027-01-01T01:00:00.000+02:00"})
		if err != nil {
			t.Fatalf("%s : %v", name, err)
		}
		var exp sql.NullString
		if err := h.DB.QueryRow(`SELECT expires_at FROM security_bans WHERE id=?`, res.(map[string]any)["id"]).Scan(&exp); err != nil {
			t.Fatal(err)
		}
		if exp.String != "2026-12-31T23:00:00Z" {
			t.Errorf("%s : expires_at=%v, attendu 2026-12-31T23:00:00Z", name, exp)
		}
	}
	var n int
	if err := h.DB.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE ip='203.0.113.40'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d ban(s) créé(s) avec une expiration invalide", n)
	}
}

func TestCreateSecurityBanScope(t *testing.T) {
	h := setupMCPDB(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if _, err := h.DB.Exec(`INSERT INTO tokens (id, token, role, node_name) VALUES ('tok-1', 's', 'edge', 'paris')`); err != nil {
		t.Fatal(err)
	}
	res, err := h.toolCreateSecurityBan(r, map[string]any{"ip": "203.0.113.50", "scope": "tok-1"})
	if err != nil {
		t.Fatal(err)
	}
	var scope string
	if err := h.DB.QueryRow(`SELECT target_scope FROM security_bans WHERE id=?`, res.(map[string]any)["id"]).Scan(&scope); err != nil || scope != "paris" {
		t.Fatalf("target_scope=%q (%v), attendu paris", scope, err)
	}
	if _, err := h.toolCreateSecurityBan(r, map[string]any{"ip": "203.0.113.51", "scope": "inconnue"}); err == nil {
		t.Error("portée inconnue acceptée")
	}
}
