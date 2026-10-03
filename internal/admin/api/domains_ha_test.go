// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestDomainEntryCanBeAnHAGroup(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "domains.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := archstore.New(t.TempDir())
	for _, n := range []archstore.NodeEntry{
		{ID: "dn_f", Role: "edge", Name: "frontal", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
		{ID: "dn_b", Role: "edge", Name: "backup", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
	} {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, tok := range [][2]string{{"tok-f", "frontal"}, {"tok-b", "backup"}} {
		if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES (?, ?, 'edge', ?, 'operator')`,
			tok[0], "secret-"+tok[0], tok[1]); err != nil {
			t.Fatal(err)
		}
	}
	h := &api.DomainsHandler{DB: db, Log: slog.Default(), Groups: api.NewGroupResolver(store, db)}

	rec := do(h, http.MethodPost, "/api/v1/domains", `{"domain":"www.exemple.fr","edge_id":"ha:ha-1","cert_method":"acme-http"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	var edgeID string
	if err := db.QueryRow(`SELECT edge_id FROM domains WHERE domain='www.exemple.fr'`).Scan(&edgeID); err != nil || edgeID != "ha:ha-1" {
		t.Fatalf("edge_id doit rester le groupe, reçu %q (%v)", edgeID, err)
	}
	for _, tok := range []string{"tok-f", "tok-b"} {
		var n int
		_ = db.QueryRow(`SELECT COUNT(*) FROM token_scopes WHERE token_id=? AND scope_type='domain'`, tok).Scan(&n)
		if n != 1 {
			t.Errorf("le membre %s doit recevoir le périmètre du domaine, scopes=%d", tok, n)
		}
	}

	if rec := do(h, http.MethodPost, "/api/v1/domains", `{"domain":"autre.fr","edge_id":"ha:inconnu","cert_method":"acme-http"}`); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "groupe HA introuvable") {
		t.Fatalf("un groupe inconnu doit être refusé : %d %s", rec.Code, rec.Body.String())
	}
}
