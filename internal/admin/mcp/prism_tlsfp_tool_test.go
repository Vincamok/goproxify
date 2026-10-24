// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func TestGetPrismTLSFingerprints(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		gw.Add(logstore.Entry{Ts: time.Now().UTC(), Component: "edge", Domain: "a.test", Method: "GET", Path: "/", Status: 200, IP: "198.51.100.7", TLSJA3: "j3", TLSJA4: "t13d_x"})
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
