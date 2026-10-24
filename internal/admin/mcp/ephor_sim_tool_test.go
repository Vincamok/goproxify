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
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

func TestSimulateEphorTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-sim.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	now := time.Now().UTC()
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	ins := func(at time.Time, ip, path string, status int, component string) {
		gw.Add(logstore.Entry{Ts: at, Component: component, Domain: "a.test", Method: "GET", Path: path, Status: status, IP: ip})
	}
	ins(now.Add(-10*time.Minute), "9.9.9.9", "/wp-admin/login", 200, "edge")
	ins(now.Add(-9*time.Minute), "9.9.9.9", "/home", 200, "edge")
	ins(now.Add(-8*time.Minute), "8.8.8.8", "/home", 200, "edge")
	ins(now.Add(-7*time.Minute), "[pseudonymisé]", "/wp-admin", 200, "edge")
	ins(now.Add(-3*time.Hour), "6.6.6.6", "/wp-admin", 200, "edge")
	gw.Add(logstore.Entry{Ts: now.Add(-5 * time.Minute), Component: "edge", Domain: "a.test", Method: "GET", Path: "/wp-admin", Status: 200, IP: "5.5.5.0", IPTruncated: true})

	h := &Handler{DB: db}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	out, err := h.toolSimulateEphor(r, map[string]any{
		"config": map[string]any{"custom_lists": map[string]any{"paths": []any{"/wp-admin"}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	m := out.(map[string]any)
	if m["events_replayed"] != 3 || m["skipped_unattributable_ip"] != 2 {
		t.Fatalf("events=%v skipped=%v", m["events_replayed"], m["skipped_unattributable_ip"])
	}
	cand := m["candidate"].(threat.SimReport)
	if cand.Blocked != 2 || cand.LegitBlocked != 2 || cand.BlockedIPs != 1 {
		t.Fatalf("candidate: %+v", cand)
	}
	if base := m["current"].(threat.SimReport); base.Blocked != 0 {
		t.Fatalf("baseline should block nothing: %+v", base)
	}
	if d := m["delta"].(map[string]int); d["blocked"] != 2 || d["bans"] != 1 {
		t.Fatalf("delta: %v", d)
	}
}

func TestSimulateEphorToolRequiresConfig(t *testing.T) {
	h := &Handler{}
	if _, err := h.toolSimulateEphor(httptest.NewRequest(http.MethodPost, "/mcp", nil), map[string]any{}); err == nil {
		t.Fatal("config manquant doit échouer")
	}
}
