// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/sqltime"
)

func TestIPTraceFollowsACIDRAcrossSources(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	ago := func(d time.Duration) time.Time { return now.Add(-d) }
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	logRow := func(at time.Time, ip string, status int, waf string) {
		exec(`INSERT INTO logs (ts, ip, domain, method, path, status, waf_matches) VALUES (?, ?, 'a.test', 'GET', '/admin', ?, ?)`,
			at.Format(time.RFC3339Nano), ip, status, waf)
	}
	// Deux épisodes à 40 jours d'écart, deux IP du /24, plus du bruit hors cible.
	logRow(ago(41*24*time.Hour), "203.0.113.5", 404, "")
	logRow(ago(41*24*time.Hour-time.Minute), "203.0.113.6", 403, `["sqli"]`)
	logRow(ago(2*time.Hour), "203.0.113.5", 200, "")
	logRow(ago(2*time.Hour), "203.0.114.5", 200, "")
	logRow(ago(2*time.Hour), "198.51.100.1", 200, "")
	exec(`INSERT INTO security_ban_history (ip, action, reason, source, created_at) VALUES ('203.0.113.5', 'banned', 'scan', 'fail2ban', ?)`, sqltime.Format(ago(41*24*time.Hour)))
	exec(`INSERT INTO security_ban_history (ip, action, reason, source, created_at) VALUES ('203.0.113.0/24', 'unbanned', '', 'native', ?)`, sqltime.Format(ago(40*24*time.Hour)))
	exec(`INSERT INTO security_ban_history (ip, action, source, created_at) VALUES ('198.51.100.1', 'banned', 'native', ?)`, sqltime.Format(ago(time.Hour)))
	exec(`INSERT INTO security_threats (ip, scenario, origin, occurrences, created_at, last_seen_at) VALUES ('203.0.113.6', 'http-probing', 'crowdsec', 3, ?, ?)`, sqltime.Format(ago(41*24*time.Hour)), sqltime.Format(ago(41*24*time.Hour)))
	exec(`INSERT INTO security_bans (id, ip, reason, source) VALUES ('b1', '203.0.113.5', 'scan', 'native')`)
	exec(`INSERT INTO ip_profiles (id, name, profile_type, mode, cidrs, enabled) VALUES ('p1', 'Scanners', 'custom', 'deny', '["203.0.113.0/25"]', 1)`)

	get := func(path string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		(&SecurityHandler{DB: db}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : %d %s", path, rec.Code, rec.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	// Défaut : 30 jours — l'épisode d'il y a 41 jours n'y est pas.
	short := get("/api/v1/security/ip-trace?target=203.0.113.0/24")
	if short["kind"] != "cidr" || short["target"] != "203.0.113.0/24" {
		t.Errorf("cible : %v / %v", short["kind"], short["target"])
	}
	if n := short["summary"].(map[string]any)["requests"].(float64); n != 1 {
		t.Errorf("30 jours : %v requêtes, attendu 1", n)
	}

	res := get("/api/v1/security/ip-trace?target=203.0.113.0/24&from=" + ago(60*24*time.Hour).Format("2006-01-02"))
	sum := res["summary"].(map[string]any)
	if sum["requests"].(float64) != 3 || sum["blocked"].(float64) != 1 || sum["ip_count"].(float64) != 2 || sum["episodes"].(float64) != 2 {
		t.Errorf("synthèse : %v", sum)
	}
	if sum["bans"].(float64) != 1 || sum["unbans"].(float64) != 1 || sum["threats"].(float64) != 1 {
		t.Errorf("bans/débans/menaces : %v", sum)
	}
	if len(sum["active_bans"].([]any)) != 1 || len(sum["profiles"].([]any)) != 1 {
		t.Errorf("état actuel : bans %v, profils %v", sum["active_bans"], sum["profiles"])
	}
	var kinds []string
	var last time.Time
	for _, s := range res["steps"].([]any) {
		step := s.(map[string]any)
		kinds = append(kinds, step["kind"].(string))
		ts, _ := time.Parse(time.RFC3339Nano, step["ts"].(string))
		if ts.Before(last) {
			t.Errorf("étapes non chronologiques : %v", step)
		}
		last = ts
	}
	// activity (41 j) + ban + threat au même instant, unban (40 j), activity (2 h) — le ban de
	// 198.51.100.1 est hors cible.
	if len(kinds) != 5 {
		t.Fatalf("étapes : %v", kinds)
	}
	if kinds[len(kinds)-1] != "activity" || kinds[len(kinds)-2] != "unban" {
		t.Errorf("ordre des étapes : %v", kinds)
	}

	// Une IP seule ne remonte pas le reste du /24, mais voit le ban posé sur le /24.
	one := get("/api/v1/security/ip-trace?target=203.0.113.5&from=" + ago(60*24*time.Hour).Format("2006-01-02"))
	if one["kind"] != "ip" || one["summary"].(map[string]any)["requests"].(float64) != 2 {
		t.Errorf("IP seule : %v", one["summary"])
	}
	if one["summary"].(map[string]any)["unbans"].(float64) != 1 {
		t.Error("le déban du /24 doit apparaître dans le parcours d'une IP qu'il contient")
	}

	// Pagination
	p := get("/api/v1/security/ip-trace?target=203.0.113.0/24&from=" + ago(60*24*time.Hour).Format("2006-01-02") + "&limit=2&offset=1")
	if len(p["steps"].([]any)) != 2 || p["total_steps"].(float64) != 5 || p["has_more"] != true {
		t.Errorf("pagination : %v", p)
	}

	rec := httptest.NewRecorder()
	(&SecurityHandler{DB: db}).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/ip-trace?target=nope", nil))
	if rec.Code != http.StatusBadRequest {
		t.Errorf("cible invalide : %d", rec.Code)
	}
}
