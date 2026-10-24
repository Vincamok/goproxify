// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Un agent qui lit list_logs puis appelle ban_ip doit savoir qu'une IP est tronquée.
func TestListLogsFlagsTruncatedIPs(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-logs.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for ip, truncated := range map[string]int{"203.0.113.0": 1, "198.51.100.7": 0} {
		if _, err := db.Exec(`INSERT INTO logs (ts, component, domain, method, path, status, ip, ip_truncated) VALUES (?, 'edge', 'a.test', 'GET', '/', 403, ?, ?)`,
			at, ip, truncated); err != nil {
			t.Fatal(err)
		}
	}

	out, err := (&Handler{DB: db}).toolListLogs(httptest.NewRequest(http.MethodPost, "/mcp", nil), "", "", "")
	if err != nil {
		t.Fatal(err)
	}
	entries := out.([]map[string]any)
	if len(entries) != 2 {
		t.Fatalf("%d entrées, attendu 2", len(entries))
	}
	for _, e := range entries {
		_, flagged := e["ip_truncated"]
		if flagged != (e["ip"] == "203.0.113.0") {
			t.Errorf("%v : ip_truncated présent = %v", e["ip"], flagged)
		}
	}
}

func TestListLogsFiltersByTLSFingerprint(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Format(time.RFC3339Nano)
	for _, ja4 := range []string{"t13d1516h2_a_b", "t13d1516h2_a_b", "t13d1517h2_c_d", ""} {
		if _, err := db.Exec(`INSERT INTO logs (ts, component, domain, method, path, status, ip, tls_ja3, tls_ja4) VALUES (?, 'edge', 'a.test', 'GET', '/', 200, '198.51.100.7', 'ja3x', ?)`, at, ja4); err != nil {
			t.Fatal(err)
		}
	}
	h := &Handler{DB: db}
	req := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	out, err := h.toolListLogsFiltered(req, "", "", "", "", "t13d1516h2_a_b")
	if err != nil {
		t.Fatal(err)
	}
	entries := out.([]map[string]any)
	if len(entries) != 2 || entries[0]["tls_ja4"] != "t13d1516h2_a_b" || entries[0]["tls_ja3"] != "ja3x" {
		t.Fatalf("filtre JA4 : %v", entries)
	}
}

// list_logs source=edge interroge les passerelles avec les mêmes filtres, rend la page fusionnée et dit ce qui manque.
func TestListLogsFromTheGateways(t *testing.T) {
	var query string
	gw := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"entries":[{"id":7,"kind":"access","ts":"2026-10-21T10:00:09.000000Z","level":"warn","component":"edge",` +
			`"domain":"a.test","method":"GET","path":"/x","status":403,"ip":"203.0.113.0","ip_truncated":true,"request_id":"req-1"}],` +
			`"next":"c","has_more":true,"partial":false}`))
	}))
	defer gw.Close()
	down := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "boom", 500) }))
	defer down.Close()

	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for id, row := range map[string][2]string{"id-a": {"gw-a", gw.URL}, "id-b": {"gw-b", down.URL}} {
		if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, ?, 'edge', ?, ?)`, id, "tok-"+id, row[0], row[1]); err != nil {
			t.Fatal(err)
		}
	}

	h := &Handler{DB: db}
	out, err := h.toolListLogsEdges(httptest.NewRequest(http.MethodPost, "/mcp", nil), map[string]any{
		"source": "edge", "domain": "a.test", "request_id": "req-1", "level": "warn",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"domain=a.test", "request_id=req-1", "level=warn"} {
		if !strings.Contains(query, want) {
			t.Errorf("la passerelle doit recevoir %q : %q", want, query)
		}
	}
	res := out.(map[string]any)
	b, _ := json.Marshal(res)
	for _, want := range []string{`"source":"edge"`, `"node_name":"gw-a"`, `"ip_truncated":true`, `"gw-b"`, `"unreachable"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("la réponse doit contenir %s : %s", want, b)
		}
	}
	if res["has_more"] != true || res["cursor"] == "" {
		t.Errorf("has_more=%v cursor=%q : une page suivante doit être proposée", res["has_more"], res["cursor"])
	}
}

func TestListLogsToolDeclaresTheGatewaySource(t *testing.T) {
	b, _ := json.Marshal(tools)
	for _, want := range []string{`"source"`, `"cursor"`, `"node"`} {
		if !strings.Contains(string(b), want) {
			t.Errorf("le schéma de list_logs doit déclarer %s", want)
		}
	}
}
