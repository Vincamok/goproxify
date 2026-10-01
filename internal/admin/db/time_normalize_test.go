// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/sqltime"
)

func TestOpenNormalizesDatesComparedToCurrentTimestamp(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Une minute plus tôt : expiré / commencé, mais le même jour UTC (sauf à minuit pile).
	at := time.Now().Add(-time.Minute).Truncate(time.Second)
	legacy := map[string]any{
		"certs":                at.UTC().Format(time.RFC3339),      // import MCP
		"silence":              at.In(time.FixedZone("", -5*3600)), // API : décalage du client, t.String()
		"tokens":               at.In(time.FixedZone("CEST", 2*3600)),
		"user_api_tokens":      at.In(time.FixedZone("", 2*3600)),
		"user_mfa_challenges":  at.In(time.FixedZone("CEST", 2*3600)),
		"user_trusted_devices": at.In(time.FixedZone("CEST", 2*3600)),
	}
	for _, q := range []struct {
		sql string
		key string
	}{
		{`INSERT INTO certs (id, domain, issuer, expires_at) VALUES ('c', 'a.fr', 'custom', ?)`, "certs"},
		{`INSERT INTO automation_silences (id, name, starts_at, ends_at) VALUES ('s', 'maintenance', ?, ?)`, "silence"},
		{`INSERT INTO tokens (id, token, role, node_name, expires_at) VALUES ('t', 'x', 'edge', 'lyon', ?)`, "tokens"},
		{`INSERT INTO user_api_tokens (id, user_id, token_hash, expires_at) VALUES ('p', 'u', 'h', ?)`, "user_api_tokens"},
		{`INSERT INTO user_mfa_challenges (id, user_id, method, expires_at) VALUES ('m', 'u', 'email', ?)`, "user_mfa_challenges"},
		{`INSERT INTO user_trusted_devices (id, user_id, token_hash, expires_at) VALUES ('d', 'u', 'h', ?)`, "user_trusted_devices"},
	} {
		args := []any{legacy[q.key]}
		if q.key == "silence" {
			args = append(args, at.Add(2*time.Hour).In(time.FixedZone("", -5*3600)))
		}
		if _, err := d.Exec(q.sql, args...); err != nil {
			t.Fatal(q.key, err)
		}
	}
	d.Close()

	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	want := sqltime.Format(at)
	for _, c := range []struct{ table, col string }{
		{"certs", "expires_at"},
		{"automation_silences", "starts_at"},
		{"tokens", "expires_at"},
		{"user_api_tokens", "expires_at"},
		{"user_mfa_challenges", "expires_at"},
		{"user_trusted_devices", "expires_at"},
	} {
		var got string
		if err := d.QueryRow(`SELECT CAST(` + c.col + ` AS TEXT) FROM ` + c.table).Scan(&got); err != nil {
			t.Fatal(c.table, err)
		}
		if got != want {
			t.Errorf("%s.%s : %q, attendu %q (UTC, format de CURRENT_TIMESTAMP)", c.table, c.col, got, want)
		}
	}
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM certs WHERE expires_at <= CURRENT_TIMESTAMP`).Scan(&n) //nolint:errcheck
	if n != 1 {
		t.Error("le certificat expiré depuis 1 min doit compter comme expiré")
	}
	d.QueryRow(`SELECT COUNT(*) FROM automation_silences WHERE starts_at <= CURRENT_TIMESTAMP AND ends_at >= CURRENT_TIMESTAMP`).Scan(&n) //nolint:errcheck
	if n != 1 {
		t.Error("le silence commencé il y a 1 min doit être actif")
	}
	d.QueryRow(`SELECT COUNT(*) FROM tokens WHERE expires_at > CURRENT_TIMESTAMP`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Error("le token expiré depuis 1 min ne doit plus être valide")
	}
}
