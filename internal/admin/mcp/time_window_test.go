// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/logs"
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
	// Les cumuls par minute que les passerelles envoient : 3 requêtes il y a une heure, 5 il y a 25 heures.
	for at, n := range map[time.Time]int{time.Now().Add(-time.Hour): 3, time.Now().Add(-25 * time.Hour): 5} {
		if _, err := h.DB.Exec(`INSERT INTO logs_minute (minute, domain, node_name, status, requests, latency_ms_sum) VALUES (?, 'a.example', 'gw-a', 200, ?, ?)`,
			logs.MinuteKey(at), n, 30*n); err != nil {
			t.Fatal(err)
		}
	}
	res, err := h.toolGetMetrics(httptest.NewRequest(http.MethodPost, "/mcp", nil), "a.example")
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["requests"] != int64(3) || m["avg_latency_ms"] != 30.0 || m["unique_ips"] != int64(0) {
		t.Errorf("get_metrics = %v, attendu 3 requêtes (celles d'il y a 25 h sont hors fenêtre), 30 ms, aucune IP sans passerelle", m)
	}
}

// Les erreurs et le taux d'erreur viennent des cumuls.
func TestGetMetricsComputesErrorsFromTheAggregates(t *testing.T) {
	h := setupMCPDB(t)
	at := logs.MinuteKey(time.Now().Add(-2 * time.Hour))
	for status, n := range map[int]int{200: 15, 502: 5} {
		if _, err := h.DB.Exec(`INSERT INTO logs_minute (minute, domain, node_name, status, requests, latency_ms_sum) VALUES (?, 'a.example', 'gw-a', ?, ?, ?)`,
			at, status, n, 30*n); err != nil {
			t.Fatal(err)
		}
	}
	res, err := h.toolGetMetrics(httptest.NewRequest(http.MethodPost, "/mcp", nil), "a.example")
	if err != nil {
		t.Fatal(err)
	}
	m := res.(map[string]any)
	if m["requests"] != int64(20) || m["errors"] != int64(5) || m["error_rate"] != 25.0 {
		t.Errorf("get_metrics = %v, attendu 20 requêtes dont 5 erreurs (25 %%)", m)
	}
}
