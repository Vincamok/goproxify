// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestParseProxyIdentity(t *testing.T) {
	id, err := parseProxyIdentity(map[string]any{"name": "alpha-1", "labels": map[string]any{"env": "prod"}})
	if err != nil || !id.hasName || !id.hasLabels || id.name != "alpha-1" || id.labels["env"] != "prod" {
		t.Fatalf("%+v %v", id, err)
	}
	if id, err := parseProxyIdentity(map[string]any{"host": "x"}); err != nil || id.hasName || id.hasLabels {
		t.Fatalf("sans nom ni étiquettes : %+v %v", id, err)
	}
	for name, args := range map[string]map[string]any{
		"nom non textuel":      {"name": 3},
		"étiquettes non objet": {"labels": "env=prod"},
		"valeur non textuelle": {"labels": map[string]any{"env": 1}},
		"clé invalide":         {"labels": map[string]any{"Env": "prod"}},
	} {
		if _, err := parseProxyIdentity(args); err == nil {
			t.Errorf("%s : devrait être refusé", name)
		}
	}
}

func TestProxyIdentityApplySetsAndClears(t *testing.T) {
	cfg := map[string]any{"name": "old", "labels": map[string]string{"a": "b"}}
	id, _ := parseProxyIdentity(map[string]any{"name": "", "labels": map[string]any{}})
	id.apply(cfg)
	if _, has := cfg["name"]; has {
		t.Fatal("un nom vide retire le nom")
	}
	if _, has := cfg["labels"]; has {
		t.Fatal("un objet vide retire les étiquettes")
	}
	id, _ = parseProxyIdentity(map[string]any{"name": "n", "labels": map[string]any{"env": "prod"}})
	id.apply(cfg)
	raw, _ := json.Marshal(cfg)
	if string(raw) != `{"labels":{"env":"prod"},"name":"n"}` {
		t.Fatalf("%s", raw)
	}
	untouched := map[string]any{"name": "keep"}
	noIdentity, _ := parseProxyIdentity(map[string]any{})
	noIdentity.apply(untouched)
	if untouched["name"] != "keep" {
		t.Fatal("sans argument, rien ne change")
	}
}

func TestSetGroupAttributesTool(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mcp-groups.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	store := archstore.New(t.TempDir())
	if err := store.Upsert(archstore.NodeEntry{ID: "e1", Role: "edge", Name: "lan-1",
		Config: json.RawMessage(`{"cluster":true,"cluster_group":"paris-lan"}`)}); err != nil {
		t.Fatal(err)
	}
	h := &Handler{DB: db, ArchStore: store}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)

	if _, err := h.toolSetGroupAttributes(r, map[string]any{"group": "inconnu"}); err == nil {
		t.Fatal("groupe inconnu")
	}
	if _, err := h.toolSetGroupAttributes(r, map[string]any{"group": "paris-lan", "environment": "pro d"}); err == nil {
		t.Fatal("environnement invalide")
	}
	if _, err := h.toolSetGroupAttributes(r, map[string]any{"group": "paris-lan", "environment": "prod", "tags": []any{"lan"}}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.toolSetGroupAttributes(r, map[string]any{"group": "paris-lan", "region": "paris"}); err != nil {
		t.Fatal(err)
	}
	a := store.GroupAttributesOf("paris-lan")
	if a.Environment != "prod" || a.Region != "paris" || len(a.Tags) != 1 {
		t.Fatalf("les attributs non fournis restent inchangés : %+v", a)
	}
	if _, err := h.toolSetGroupAttributes(r, map[string]any{"group": "paris-lan", "tags": []any{}}); err != nil {
		t.Fatal(err)
	}
	if a := store.GroupAttributesOf("paris-lan"); len(a.Tags) != 0 || a.Environment != "prod" {
		t.Fatalf("un tableau vide retire les tags : %+v", a)
	}
}
