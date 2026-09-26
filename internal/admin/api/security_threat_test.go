// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"path/filepath"
	"time"

	"database/sql"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func TestThreatConfigIsStoredAndPushedPerEdge(t *testing.T) {
	db, err := sql.Open("sqlite", "file:threat_cfg_test?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}

	var pushedTo []string
	h := &api.SecurityHandler{
		DB:                   db,
		OnThreatConfigChange: func(edgeRef string, _ any) { pushedTo = append(pushedTo, edgeRef) },
	}

	put := func(query string) {
		t.Helper()
		req := httptest.NewRequest(http.MethodPut, "/api/v1/security/threat-config"+query, strings.NewReader(`{"enabled":true}`))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		if rec.Code != http.StatusNoContent {
			t.Fatalf("PUT%s: %d %s", query, rec.Code, rec.Body.String())
		}
	}
	get := func(query string) string {
		t.Helper()
		req := httptest.NewRequest(http.MethodGet, "/api/v1/security/threat-config"+query, nil)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return strings.TrimSpace(rec.Body.String())
	}

	put("?edge=edge-b")

	if got := get("?edge=edge-b"); got != `{"enabled":true}` {
		t.Fatalf("config de la passerelle: %q", got)
	}
	if got := get(""); got != `{"enabled":false}` {
		t.Fatalf("la config globale ne doit pas être touchée par une écriture par passerelle: %q", got)
	}
	if len(pushedTo) != 1 || pushedTo[0] != "edge-b" {
		t.Fatalf("push visé sur edge-b uniquement, reçu %v", pushedTo)
	}

	put("")
	if len(pushedTo) != 2 || pushedTo[1] != "" {
		t.Fatalf("écriture globale : push à tous (edgeRef vide), reçu %v", pushedTo)
	}
}

func TestSimulateThreatEndpoint(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "sim.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	at := time.Now().UTC().Add(-5 * time.Minute).Format(time.RFC3339Nano)
	if _, err := db.Exec(`INSERT INTO logs (ts, component, domain, method, path, status, ip) VALUES (?, 'edge', 'a.test', 'GET', '/wp-admin/x', 200, '9.9.9.9')`, at); err != nil {
		t.Fatal(err)
	}
	h := &api.SecurityHandler{DB: db}

	body := `{"config":{"enabled":true,"custom_lists":{"paths":["/wp-admin"]}},"hours":1}`
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/simulate", strings.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST simulate: %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Replayed int            `json:"events_replayed"`
		Delta    map[string]int `json:"delta"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Replayed != 1 || out.Delta["legit_blocked"] != 1 {
		t.Fatalf("résultat inattendu : %s", rec.Body.String())
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/simulate", strings.NewReader(`{}`)))
	if rec.Code != http.StatusBadRequest {
		t.Fatalf("config absente : %d", rec.Code)
	}
}
