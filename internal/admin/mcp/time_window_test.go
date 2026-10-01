// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestSecurityToolsIgnoreBansExpiredAMinuteAgo(t *testing.T) {
	h := setupMCPDB(t)
	for id, exp := range map[string]time.Time{"expire": time.Now().Add(-time.Minute), "actif": time.Now().Add(time.Hour)} {
		if _, err := h.DB.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES (?, '203.0.113.30', 'threat', ?)`,
			id, exp.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ov, err := h.toolGetSecurityOverview(r)
	if err != nil {
		t.Fatal(err)
	}
	if n := ov.(map[string]any)["active_bans"]; n != 1 {
		t.Errorf("get_security_overview : %v bans actifs, attendu 1", n)
	}
	list, err := h.toolListSecurityBans(r, map[string]any{"active_only": true})
	if err != nil {
		t.Fatal(err)
	}
	if bans := list.([]map[string]any); len(bans) != 1 || bans[0]["id"] != "actif" {
		t.Errorf("list_security_bans active_only : %v, attendu le seul ban non expiré", bans)
	}
}

func TestGetMetricsCoversTheLast24HoursOnly(t *testing.T) {
	h := setupMCPDB(t)
	for at, n := range map[time.Time]int{time.Now().Add(-time.Hour): 3, time.Now().Add(-25 * time.Hour): 5} {
		for i := 0; i < n; i++ {
			if _, err := h.DB.Exec(`INSERT INTO logs (ts, domain, status, ip) VALUES (?, 'a.example', 200, '203.0.113.31')`,
				at.UTC().Format(time.RFC3339Nano)); err != nil {
				t.Fatal(err)
			}
		}
	}
	res, err := h.toolGetMetrics(httptest.NewRequest(http.MethodPost, "/mcp", nil), "a.example")
	if err != nil {
		t.Fatal(err)
	}
	if n := res.(map[string]any)["requests"]; n != int64(3) {
		t.Errorf("get_metrics : %v requêtes, attendu 3 (celles d'il y a 25 h sont hors fenêtre)", n)
	}
}
