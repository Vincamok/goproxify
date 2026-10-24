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

// Une délégation relie deux groupes différents : elle est refusée entre deux membres d'un même groupe, d'un groupe vers
// l'un de ses membres, ou d'une passerelle vers elle-même ; elle est acceptée vers un autre groupe ou une passerelle seule.
func TestDelegationMustLinkDifferentGroups(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "domains.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := archstore.New(t.TempDir())
	for _, n := range []archstore.NodeEntry{
		{ID: "dn_f", Role: "edge", Name: "frontal", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
		{ID: "dn_b", Role: "edge", Name: "backup", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
		{ID: "dn_o", Role: "edge", Name: "ailleurs", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-2"}`)},
		{ID: "dn_s", Role: "edge", Name: "seul"},
	} {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	for _, tok := range [][2]string{{"tok-f", "frontal"}, {"tok-b", "backup"}, {"tok-o", "ailleurs"}, {"tok-s", "seul"}} {
		if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, rbac_role) VALUES (?, ?, 'edge', ?, 'operator')`,
			tok[0], "secret-"+tok[0], tok[1]); err != nil {
			t.Fatal(err)
		}
	}
	h := &api.DomainsHandler{DB: db, Log: slog.Default(), Groups: api.NewGroupResolver(store, db)}
	create := func(domain, entry, target string) *httptest.ResponseRecorder {
		return do(h, http.MethodPost, "/api/v1/domains", `{"domain":"`+domain+`","edge_id":"`+entry+`","delegated_to_edge_id":"`+target+`","delegated_endpoint":"https://x:443","cert_method":"acme-http"}`)
	}

	for _, c := range []struct{ name, entry, target string }{
		{"membre vers membre du même groupe", "tok-f", "tok-b"},
		{"groupe vers un de ses membres", "ha:ha-1", "tok-b"},
		{"passerelle vers elle-même", "tok-s", "tok-s"},
	} {
		rec := create(strings.ReplaceAll(c.name, " ", "-")+".fr", c.entry, c.target)
		if rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "délégation relie") {
			t.Errorf("%s doit être refusée : %d %s", c.name, rec.Code, rec.Body.String())
		}
	}
	for _, c := range []struct{ name, entry, target string }{
		{"groupe-vers-autre-groupe", "ha:ha-1", "tok-o"},
		{"membre-vers-passerelle-seule", "tok-f", "tok-s"},
		{"seule-vers-groupe", "tok-s", "tok-b"},
	} {
		if rec := create(c.name+".fr", c.entry, c.target); rec.Code != http.StatusCreated {
			t.Errorf("%s doit être acceptée : %d %s", c.name, rec.Code, rec.Body.String())
		}
	}

	// Une mise à jour est soumise à la même règle.
	var id string
	_ = db.QueryRow(`SELECT id FROM domains WHERE domain='groupe-vers-autre-groupe.fr'`).Scan(&id)
	rec := do(h, http.MethodPut, "/api/v1/domains/"+id, `{"domain":"groupe-vers-autre-groupe.fr","edge_id":"ha:ha-1","delegated_to_edge_id":"tok-f","delegated_endpoint":"https://x:443","cert_method":"acme-http"}`)
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("la mise à jour vers un membre du même groupe est refusée : %d %s", rec.Code, rec.Body.String())
	}
}
