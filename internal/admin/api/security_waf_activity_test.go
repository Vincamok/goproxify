// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func TestWAFActivityCountsFlaggedRequests(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	recent := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	log := func(ts, node, domain string, status int, waf string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO logs (ts, node_name, domain, method, path, status, waf_matches) VALUES (?, ?, ?, 'GET', '/x', ?, ?)`, ts, node, domain, status, waf); err != nil {
			t.Fatal(err)
		}
	}
	log(recent, "gw-a", "a.test", 403, `["942100","941100"]`)
	log(recent, "gw-a", "a.test", 403, `["942100"]`)
	log(recent, "gw-a", "b.test", 200, `["942100"]`) // mode détection : passée
	log(recent, "gw-b", "c.test", 403, `["930100"]`)
	log(recent, "gw-a", "a.test", 200, ``)        // propre : ignorée
	log(old, "gw-a", "a.test", 403, `["942100"]`) // hors fenêtre de 24 h

	get := func(q string) api.WAFActivity {
		t.Helper()
		rec := serveBans(h, http.MethodGet, "/api/v1/security/waf-activity"+q, "")
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : %d %s", q, rec.Code, rec.Body)
		}
		var a api.WAFActivity
		if err := json.Unmarshal(rec.Body.Bytes(), &a); err != nil {
			t.Fatal(err)
		}
		return a
	}

	all := get("")
	if all.Hours != 24 || all.Requests != 4 || all.Blocked != 3 || all.Detected != 1 {
		t.Fatalf("toutes passerelles : %+v", all)
	}
	if len(all.TopRules) == 0 || all.TopRules[0].Name != "942100" || all.TopRules[0].Count != 3 {
		t.Fatalf("règle la plus fréquente : %+v", all.TopRules)
	}
	if len(all.TopDomains) == 0 || all.TopDomains[0].Name != "a.test" || all.TopDomains[0].Count != 2 {
		t.Fatalf("domaine le plus touché : %+v", all.TopDomains)
	}

	if one := get("?edge=gw-b"); one.Requests != 1 || one.TopRules[0].Name != "930100" {
		t.Fatalf("gw-b : %+v", one)
	}
	if wide := get("?hours=96"); wide.Requests != 5 || wide.Hours != 96 {
		t.Fatalf("96 h : %+v", wide)
	}
	if capped := get("?hours=100000"); capped.Hours != 168 {
		t.Fatalf("fenêtre plafonnée : %d", capped.Hours)
	}
	if none := get("?edge=inconnue"); none.Requests != 0 || none.TopRules == nil {
		t.Fatalf("passerelle sans activité : %+v", none)
	}
}

// La requête doit passer par l'index partiel : sans lui, elle lirait toute la table des journaux.
func TestWAFActivityUsesThePartialIndex(t *testing.T) {
	db := openBansDB(t)
	rows, err := db.Query(`EXPLAIN QUERY PLAN SELECT domain, status, waf_matches FROM logs INDEXED BY idx_logs_waf_ts
		WHERE waf_matches != '' AND ts >= ? ORDER BY ts DESC LIMIT 10`, "2026-01-01T00:00:00Z")
	if err != nil {
		t.Fatalf("index absent ou inutilisable : %v", err)
	}
	defer rows.Close()
	var plan strings.Builder
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan.WriteString(detail + "\n")
	}
	if !strings.Contains(plan.String(), "idx_logs_waf_ts") {
		t.Fatalf("plan : %s", plan.String())
	}
}
