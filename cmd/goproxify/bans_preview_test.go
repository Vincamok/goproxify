// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestBansPreviewPath(t *testing.T) {
	got := bansPreviewPath(map[string]string{"-ip": "203.0.113.0/24", "-hours": "48"})
	if got != "/api/v1/security/bans/preview?hours=48&ip=203.0.113.0%2F24" {
		t.Fatalf("chemin : %s", got)
	}
	if got := bansPreviewPath(map[string]string{"-ip": "203.0.113.9"}); strings.Contains(got, "hours") {
		t.Fatalf("hours absent attendu : %s", got)
	}
}

func TestFormatBanPreview(t *testing.T) {
	var res map[string]any
	raw := `{"target":"203.0.113.0/24","kind":"cidr","addresses":256,"hours":24,"requests":8,"ips":2,"blocked":6,"ok_requests":2,"ok_ips":1,
	"top_ips":[{"value":"203.0.113.5","count":6}],
	"existing_bans":[{"ip":"203.0.0.0/16","source":"native","relation":"covers"}],
	"profiles":[{"name":"Partenaires","mode":"allow"}],
	"warnings":["déjà couvert par le ban 203.0.0.0/16"]}`
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatal(err)
	}
	out := formatBanPreview(res)
	for _, want := range []string{"203.0.113.0/24 (cidr, 256 adresse(s))", "8 requête(s) de 2 adresse(s)", "2 réussie(s) de 1 adresse(s)",
		"203.0.113.5 (6)", "203.0.0.0/16 (native, covers)", "Partenaires (allow)", "! déjà couvert"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de :\n%s", want, out)
		}
	}
	if !strings.Contains(formatBanPreview(map[string]any{"target": "1.2.3.4", "kind": "ip", "addresses": 1.0}), "Aucun avertissement") {
		t.Error("cas sans avertissement")
	}
}

func TestBansWhitelistPath(t *testing.T) {
	if got := bansWhitelistPath(""); got != "/api/v1/security/bans/whitelist" {
		t.Fatalf("liste : %s", got)
	}
	if got := bansWhitelistPath("203.0.113.0/24"); got != "/api/v1/security/bans/whitelist?ip=203.0.113.0%2F24" {
		t.Fatalf("retrait : %s", got)
	}
}

func TestBansImportPayload(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	p, err := bansImportPayload("203.0.113.5\n", map[string]string{"-format": "text", "-target": "whitelist", "-reason": "partenaires", "-ttl": "7d", "-dry-run": ""}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p["content"] != "203.0.113.5\n" || p["format"] != "text" || p["target"] != "whitelist" || p["reason"] != "partenaires" ||
		p["expires_at"] != "2026-01-08T12:00:00Z" || p["dry_run"] != true {
		t.Fatalf("corps : %v", p)
	}
	if p, _ := bansImportPayload("x", map[string]string{}, now); p["dry_run"] != nil || p["expires_at"] != nil || len(p) != 1 {
		t.Fatalf("options absentes : %v", p)
	}
	if _, err := bansImportPayload("x", map[string]string{"-ttl": "demain"}, now); err == nil {
		t.Fatal("-ttl invalide")
	}
}

func TestFormatBansImport(t *testing.T) {
	var res map[string]any
	raw := `{"dry_run":true,"target":"bans","format":"text","total":5,"created":2,"addresses":257,"skipped_count":1,"rejected_count":1,
	"skipped":[{"line":3,"value":"203.0.113.5","reason":"doublon dans la liste"}],
	"rejected":[{"line":4,"value":"pas-une-ip","reason":"IP ou CIDR invalide"}]}`
	if err := json.Unmarshal([]byte(raw), &res); err != nil {
		t.Fatal(err)
	}
	out := formatBansImport(res)
	for _, want := range []string{"dry-run", "5 entrée(s) lue(s)", "Seraient créées : 2 (257 adresse(s))", "ignorées : 1", "rejetées : 1",
		"ligne 4  pas-une-ip  — IP ou CIDR invalide", "ligne 3  203.0.113.5  — doublon dans la liste"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de :\n%s", want, out)
		}
	}
	res["dry_run"] = false
	if out := formatBansImport(res); strings.Contains(out, "dry-run") || !strings.Contains(out, "Créées : 2") {
		t.Errorf("import réel :\n%s", out)
	}
}

func TestBansScopeFlag(t *testing.T) {
	p, err := bansAddPayload(map[string]string{"-ip": "203.0.113.5", "-scope": "group:ha-1"}, time.Now())
	if err != nil || p["target_scope"] != "group:ha-1" {
		t.Fatalf("add : %v %v", p, err)
	}
	if p, _ := bansAddPayload(map[string]string{"-ip": "203.0.113.5"}, time.Now()); p["target_scope"] != nil {
		t.Fatalf("portée absente : %v", p)
	}
	if got := bansListPath(map[string]string{"-scope": "paris"}); got != "/api/v1/security/bans?scope=paris" {
		t.Fatalf("liste : %s", got)
	}
	if p, _ := bansImportPayload("x", map[string]string{"-scope": "paris"}, time.Now()); p["scope"] != "paris" {
		t.Fatalf("import : %v", p)
	}
	if got := bansEdgeSuffix(map[string]any{"edge_name": "a", "target_scope": "group:g"}); got != "  [a]  → group:g" {
		t.Fatalf("suffixe : %q", got)
	}
}
