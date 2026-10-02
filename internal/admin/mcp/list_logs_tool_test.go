// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
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
