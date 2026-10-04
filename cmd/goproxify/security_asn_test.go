// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"time"
)

func TestASNPaths(t *testing.T) {
	if got := asnLookupPath("OVH SAS"); got != "/api/v1/security/asn?q=OVH+SAS" {
		t.Errorf("lookup : %s", got)
	}
	if got := asnPreviewPath(map[string]string{"-asn": "AS16276", "-hours": "48"}); got != "/api/v1/security/asn/preview?asn=AS16276&hours=48" {
		t.Errorf("preview : %s", got)
	}
	if got := asnPreviewPath(map[string]string{"-asn": "16276"}); strings.Contains(got, "hours") {
		t.Errorf("hours absent attendu : %s", got)
	}
}

func TestASNBanPayload(t *testing.T) {
	now := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	p, err := asnBanPayload(map[string]string{"-asn": "AS16276", "-reason": "scans", "-ttl": "7d", "-scope": "group:ha-1", "-dry-run": ""}, now)
	if err != nil {
		t.Fatal(err)
	}
	if p["asn"] != "AS16276" || p["reason"] != "scans" || p["scope"] != "group:ha-1" || p["expires_at"] != "2026-01-08T12:00:00Z" || p["dry_run"] != true {
		t.Fatalf("corps : %v", p)
	}
	if p, _ := asnBanPayload(map[string]string{"-asn": "1"}, now); len(p) != 1 {
		t.Errorf("options absentes : %v", p)
	}
	if _, err := asnBanPayload(map[string]string{"-asn": "1", "-ttl": "demain"}, now); err == nil {
		t.Error("-ttl invalide accepté")
	}
}

func TestFormatASN(t *testing.T) {
	var list []map[string]any
	_ = json.Unmarshal([]byte(`[{"asn":16276,"name":"OVH","country":"FR","ranges":593,"v4_addresses":4643582,"v6_ranges":4,"banned_ranges":2}]`), &list)
	out := formatASNLookup(list)
	for _, want := range []string{"AS16276  OVH (FR)", "593 plage(s)", "4643582 adresse(s) IPv4", "4 plage(s) IPv6", "[2 plage(s) bannie(s)]"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de : %s", want, out)
		}
	}
	if !strings.Contains(formatASNLookup(nil), "aucun ASN") {
		t.Error("liste vide")
	}

	var prev map[string]any
	_ = json.Unmarshal([]byte(`{"asn":{"asn":64500,"name":"X","country":"FR","v4_addresses":512,"v6_ranges":1},"hours":24,"would_create":3,"skipped_count":1,
		"rejected_count":0,"too_wide":0,"requests":8,"ips":2,"blocked":6,"ok_requests":2,"ok_ips":1,"top_ips":[{"value":"5.0.0.9","count":6}],"warnings":["l'ASN contient votre adresse"]}`), &prev)
	out = formatASNPreview(prev)
	for _, want := range []string{"AS64500 X (FR)", "3 à bannir", "ignorées : 1", "8 requête(s) de 2 adresse(s)", "5.0.0.9 (6)", "! l'ASN contient votre adresse"} {
		if !strings.Contains(out, want) {
			t.Errorf("%q absent de : %s", want, out)
		}
	}

	var ban map[string]any
	_ = json.Unmarshal([]byte(`{"dry_run":true,"asn":64500,"name":"X","country":"FR","announced_ranges":3,"prefixes":4,"created":3,"skipped_count":1,"rejected_count":0,"too_wide":0}`), &ban)
	out = formatASNBan(ban)
	if !strings.Contains(out, "Simulation") || !strings.Contains(out, "Seraient créées : 3") {
		t.Errorf("ban : %s", out)
	}
	ban["dry_run"] = false
	if out := formatASNBan(ban); strings.Contains(out, "Simulation") || !strings.Contains(out, "Créées : 3") {
		t.Errorf("ban réel : %s", out)
	}
}
