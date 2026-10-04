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
	"github.com/vincamok/goproxify/internal/admin/analytics"
)

func TestGetPrismTLSFingerprints(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	at := time.Now().UTC().Format(time.RFC3339)
	for i := 0; i < 3; i++ {
		if _, err := db.Exec(`INSERT INTO logs (ts, component, domain, method, path, status, ip, tls_ja3, tls_ja4) VALUES (?, 'edge', 'a.test', 'GET', '/', 200, '198.51.100.7', 'j3', 't13d_x')`, at); err != nil {
			t.Fatal(err)
		}
	}
	out, err := (&Handler{DB: db}).toolGetPrismTLSFingerprints(httptest.NewRequest(http.MethodPost, "/mcp", nil), map[string]any{"hours": float64(1)})
	if err != nil {
		t.Fatal(err)
	}
	rows := out.([]analytics.TLSFingerprintEntry)
	if len(rows) != 1 || rows[0].JA4 != "t13d_x" || rows[0].Requests != 3 || rows[0].UniqueIPs != 1 {
		t.Fatalf("empreintes : %+v", rows)
	}
}
