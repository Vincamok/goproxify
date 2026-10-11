// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"reflect"
	"testing"
)

func TestKeyValuesKeepTypes(t *testing.T) {
	got := keyValues("cvss=8.5, cron=0 3 * * *,on=true,ip=1.2.3.4,vide=")
	want := map[string]any{"cvss": 8.5, "cron": "0 3 * * *", "on": true, "ip": "1.2.3.4", "vide": ""}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("%v", got)
	}
}

func TestFlowSummary(t *testing.T) {
	f := map[string]any{
		"trigger": map[string]any{"kind": "schedule", "schedule": map[string]any{"cron": "0 3 * * *"}},
		"steps":   []any{map[string]any{"type": "approval"}, map[string]any{"type": "action", "action": map[string]any{"type": "run_backup"}}},
	}
	if got := flowSummary(f); got != "cron 0 3 * * * → approval → run_backup" {
		t.Fatal(got)
	}
}

func TestChangeText(t *testing.T) {
	for want, c := range map[string]map[string]any{
		"étape s2 ajoutée : notify":        {"kind": "step_added", "step_id": "s2", "detail": "notify"},
		"flux désactivé":                   {"kind": "enabled", "detail": "false"},
		"garde-fou modifié (cooldown_sec)": {"kind": "guard", "detail": "cooldown_sec"},
		"plus ancienne version conservée":  {"kind": "earliest_kept"},
	} {
		if got := changeText(c); got != want {
			t.Errorf("%v : %q", c, got)
		}
	}
}
