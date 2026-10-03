// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"net/http"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func TestNormalizeBanScope(t *testing.T) {
	db, store := groupFixture(t, "banscope")
	if _, err := db.Exec(`CREATE TABLE tokens (id TEXT, node_name TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tokens (id, node_name) VALUES ('tok-1', 'frontal')`); err != nil {
		t.Fatal(err)
	}
	groups := api.NewGroupResolver(store, db)

	for raw, want := range map[string]string{"": "", "  ": "", "frontal": "frontal", "tok-1": "frontal", "group:ha-1": "group:ha-1"} {
		got, err := api.NormalizeBanScope(db, groups, raw)
		if err != nil || got != want {
			t.Errorf("%q : %q, %v (attendu %q)", raw, got, err, want)
		}
	}
	for _, raw := range []string{"inconnue", "group:nope", "group:"} {
		if _, err := api.NormalizeBanScope(db, groups, raw); err == nil {
			t.Errorf("%q devrait être refusé", raw)
		}
	}
	if _, err := api.NormalizeBanScope(db, nil, "group:ha-1"); err == nil {
		t.Error("groupe sans résolveur : refus attendu")
	}
}

func TestCreateAndImportBansStoreTheirScope(t *testing.T) {
	db := openBansDB(t)
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name) VALUES ('tok-1', 'secret-1', 'edge', 'paris')`); err != nil {
		t.Fatal(err)
	}
	h := &api.SecurityHandler{DB: db}

	if rec := serveBans(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.113.5","target_scope":"tok-1"}`); rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body)
	}
	if rec := serveBans(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.113.6","target_scope":"nulle-part"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("portée inconnue : %d %s", rec.Code, rec.Body)
	}
	res, code, body := doImport(t, h, api.ImportRequest{Content: "198.51.100.0/24\n", Scope: "paris"}, "192.0.2.1:1")
	if code != http.StatusOK || res.Created != 1 {
		t.Fatalf("import : %d %s", code, body)
	}
	if _, code, _ := doImport(t, h, api.ImportRequest{Content: "198.51.101.0/24\n", Scope: "nulle-part"}, "192.0.2.1:1"); code != http.StatusBadRequest {
		t.Fatalf("import, portée inconnue : %d", code)
	}

	rows, err := db.Query(`SELECT ip, target_scope FROM security_bans ORDER BY ip`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	got := map[string]string{}
	for rows.Next() {
		var ip, scope string
		_ = rows.Scan(&ip, &scope)
		got[ip] = scope
	}
	if len(got) != 2 || got["203.0.113.5"] != "paris" || got["198.51.100.0/24"] != "paris" {
		t.Fatalf("bans : %v", got)
	}

	rec := serveBans(h, http.MethodGet, "/api/v1/security/bans?scope=paris", "")
	if rec.Code != http.StatusOK || strings.Count(rec.Body.String(), `"target_scope":"paris"`) != 2 {
		t.Fatalf("liste : %d %s", rec.Code, rec.Body)
	}
}
