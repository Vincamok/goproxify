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
	"github.com/vincamok/goproxify/internal/admin/archstore"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func newDomainsForSecrets(t *testing.T) (http.Handler, func(string) string) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "domains.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	store := archstore.New(t.TempDir())
	if err := store.Upsert(archstore.NodeEntry{ID: "dn_f", Role: "edge", Name: "frontal", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)}); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('su','su@x.fr','x','superadmin')`); err != nil {
		t.Fatal(err)
	}
	h := adminauth.RequireJWT("secret")(&api.DomainsHandler{DB: db, Log: slog.Default(), Groups: api.NewGroupResolver(store, db)})
	stored := func(domain string) string {
		var c string
		_ = db.QueryRow(`SELECT dns_credentials FROM domains WHERE domain=?`, domain).Scan(&c)
		return c
	}
	return h, stored
}

// Les identifiants DNS d'un domaine ne sortent jamais en clair ; renvoyer le masque ou les omettre les conserve.
func TestDomains_DNSCredentialsAreMaskedAndKept(t *testing.T) {
	h, stored := newDomainsForSecrets(t)
	rec := doAs(h, http.MethodPost, "/api/v1/domains", `{"domain":"a.exemple.fr","edge_id":"ha:ha-1","dns_provider":"cloudflare","cert_method":"acme-dns","dns_credentials":{"api_token":"CF-SECRET","zone_id":"Z1"}}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("POST: %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	for _, path := range []string{"/api/v1/domains", "/api/v1/domains/" + created.ID} {
		out := doAs(h, http.MethodGet, path, "").Body.String()
		if !strings.Contains(out, "a.exemple.fr") {
			t.Fatalf("GET %s ne renvoie pas le domaine : %s", path, out)
		}
		if strings.Contains(out, "CF-SECRET") {
			t.Errorf("GET %s renvoie le jeton en clair : %s", path, out)
		}
	}
	if out := doAs(h, http.MethodGet, "/api/v1/domains/"+created.ID, "").Body.String(); !strings.Contains(out, "Z1") {
		t.Errorf("les champs non secrets doivent rester visibles : %s", out)
	}

	put := func(body string) {
		t.Helper()
		if rec := doAs(h, http.MethodPut, "/api/v1/domains/"+created.ID, body); rec.Code >= 300 {
			t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
		}
	}
	put(`{"domain":"a.exemple.fr","edge_id":"ha:ha-1","dns_provider":"cloudflare","cert_method":"acme-dns","dns_credentials":{"api_token":"••••••••","zone_id":"Z2"}}`)
	if c := stored("a.exemple.fr"); !strings.Contains(c, "CF-SECRET") || !strings.Contains(c, "Z2") {
		t.Errorf("masque renvoyé : jeton perdu ou zone non mise à jour : %s", c)
	}
	put(`{"domain":"a.exemple.fr","edge_id":"ha:ha-1","dns_provider":"cloudflare","cert_method":"acme-dns"}`)
	if c := stored("a.exemple.fr"); !strings.Contains(c, "CF-SECRET") {
		t.Errorf("identifiants omis : effacés (%s)", c)
	}
	put(`{"domain":"a.exemple.fr","edge_id":"ha:ha-1","dns_provider":"hetzner","cert_method":"acme-dns","dns_credentials":{"api_token":"••••••••"}}`)
	if c := stored("a.exemple.fr"); strings.Contains(c, "CF-SECRET") || strings.Contains(c, "••••") {
		t.Errorf("changement de fournisseur : le jeton de l'ancien ne doit pas être repris, ni le masque stocké : %s", c)
	}
	put(`{"domain":"a.exemple.fr","edge_id":"ha:ha-1","dns_provider":"hetzner","cert_method":"acme-dns","dns_credentials":{"api_token":"NOUVEAU"}}`)
	if c := stored("a.exemple.fr"); !strings.Contains(c, "NOUVEAU") {
		t.Errorf("secret retapé non enregistré : %s", c)
	}
}

func doAs(h http.Handler, method, url, body string) *httptest.ResponseRecorder {
	tok, _ := adminauth.SignJWT("su", "secret", time.Hour)
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}
