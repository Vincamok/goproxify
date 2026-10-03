// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestImportSecurityBansTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	var pushes atomic.Int32
	h := &Handler{DB: db, OnBansChange: func() { pushes.Add(1) }}
	r := httptest.NewRequest("POST", "/mcp", nil)
	r.RemoteAddr = "192.0.2.1:1"

	out, err := h.toolImportSecurityBans(r, map[string]any{"content": "203.0.113.5\n198.51.100.0/24\npas-une-ip\n", "dry_run": true})
	if err != nil {
		t.Fatal(err)
	}
	res := out.(api.ImportResult)
	if !res.DryRun || res.Created != 2 || res.RejectedCount != 1 || pushes.Load() != 0 {
		t.Fatalf("analyse : %+v poussées=%d", res, pushes.Load())
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_bans`).Scan(&n)
	if n != 0 {
		t.Fatalf("dry_run a créé %d ban(s)", n)
	}

	out, err = h.toolImportSecurityBans(r, map[string]any{"content": "203.0.113.5\n198.51.100.0/24\n", "reason": "scan"})
	if err != nil {
		t.Fatal(err)
	}
	if res = out.(api.ImportResult); res.Created != 2 || pushes.Load() != 1 {
		t.Fatalf("import : %+v poussées=%d", res, pushes.Load())
	}
	if _, err := h.toolImportSecurityBans(r, map[string]any{"content": ""}); err == nil {
		t.Fatal("liste vide : erreur attendue")
	}
}
