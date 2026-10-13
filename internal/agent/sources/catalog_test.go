// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"io"
	"log/slog"
	"reflect"
	"testing"

	"github.com/vincamok/goproxify/internal/agent/edgeset"
	"github.com/vincamok/goproxify/internal/config"
)

func catalogDeps(sections map[string]map[string]any) Deps {
	cfg := &config.AgentConfig{Sources: sections}
	cfg.ControlPlane.EdgeEndpoint = "http://edge:8000"
	cfg.Identity.NodeName = "node-a"
	return Deps{Cfg: cfg, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Edges: edgeset.New("http://edge:8000", "")}
}

func TestCatalogSources_EnabledOnlyWhenConfigured(t *testing.T) {
	// Sans section, ou section désactivée : aucune source.
	if out := BuildBuiltin(catalogDeps(nil)); len(out) != 0 {
		t.Fatalf("sans configuration : %d sources", len(out))
	}
	if out := BuildBuiltin(catalogDeps(map[string]map[string]any{"consul": {"enabled": false, "address": "http://c:8500"}})); len(out) != 0 {
		t.Fatalf("désactivée : %d sources", len(out))
	}

	out := BuildBuiltin(catalogDeps(map[string]map[string]any{
		"consul": {"enabled": true, "address": "http://c:8500", "token": "t", "poll_interval_s": float64(20)},
		"nomad":  {"enabled": true},
		"etcd":   {"enabled": true, "endpoints": []any{"http://e1:2379", "http://e2:2379"}},
		"ecs":    {"enabled": true, "region": "eu-west-1", "cluster": "prod"},
	}))
	var types []string
	for _, s := range out {
		types = append(types, s.Type)
		if !s.Blocking || s.SetToken == nil || s.Reannounce == nil || !reflect.DeepEqual(s.Runtimes, []string{s.Type}) {
			t.Errorf("%s : instance incomplète %+v", s.Type, s)
		}
	}
	if !reflect.DeepEqual(types, []string{"consul", "nomad", "etcd", "ecs"}) {
		t.Fatalf("sources construites = %v", types)
	}
}

// Une configuration invalide n'empêche pas les autres sources de démarrer.
func TestCatalogSources_InvalidSectionIsSkipped(t *testing.T) {
	out := BuildBuiltin(catalogDeps(map[string]map[string]any{
		"ecs":    {"enabled": true, "region": "eu-west-1"}, // cluster requis
		"consul": {"enabled": true},
	}))
	if len(out) != 1 || out[0].Type != "consul" {
		t.Fatalf("sources = %+v", out)
	}
}

func TestCatalogSources_SecretsAreDeclared(t *testing.T) {
	secrets := map[string]bool{}
	for _, k := range BuiltinSecretKeys() {
		secrets[k] = true
	}
	for _, k := range []string{"token", "password", "access_key_id", "secret_access_key", "session_token"} {
		if !secrets[k] {
			t.Errorf("%s doit être déclaré secret", k)
		}
	}
}

func TestSettingHelpers(t *testing.T) {
	m := map[string]any{"a": " x ", "n1": 7, "n2": float64(9), "n3": "11", "b1": true, "b2": "TRUE", "l1": []any{"a", "b"}, "l2": "a, b", "l3": []string{"c"}}
	if settingString(m, "a") != "x" || settingString(m, "absent") != "" {
		t.Error("settingString")
	}
	if settingInt(m, "n1") != 7 || settingInt(m, "n2") != 9 || settingInt(m, "n3") != 11 || settingInt(m, "absent") != 0 {
		t.Error("settingInt")
	}
	if !settingBool(m, "b1") || !settingBool(m, "b2") || settingBool(m, "absent") {
		t.Error("settingBool")
	}
	if len(settingList(m, "l1")) != 2 || len(settingList(m, "l2")) != 2 || len(settingList(m, "l3")) != 1 {
		t.Error("settingList")
	}
	if pollInterval(map[string]any{}).Seconds() != 30 || pollInterval(map[string]any{"poll_interval_s": 1}).Seconds() != 5 {
		t.Error("pollInterval")
	}
}
