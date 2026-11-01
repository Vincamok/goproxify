// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"testing"
)

func asMap(t *testing.T, v any) map[string]any {
	t.Helper()
	b, _ := json.Marshal(v)
	var m map[string]any
	if err := json.Unmarshal(b, &m); err != nil {
		t.Fatalf("%s : %v", b, err)
	}
	return m
}

func TestTeamAccessTools(t *testing.T) {
	h := setupMCPDB(t)
	r := adminRequest(t, h)
	if _, err := h.DB.Exec(`INSERT INTO teams (id, name) VALUES ('ops','Ops')`); err != nil {
		t.Fatal(err)
	}

	cat := asMap(t, mustTool(t)(h.toolGetRightsCatalog(r)))
	if len(cat["services"].([]any)) < 30 || len(cat["profiles"].([]any)) < 10 {
		t.Fatalf("catalogue : %v", cat)
	}

	// Un profil, surchargé service par service, sur un périmètre d'étiquette.
	created := asMap(t, mustTool(t)(h.toolSetTeamAccess(r, map[string]any{
		"team": "ops", "name": "Exploitation prod", "profile": "operations",
		"perimeter": map[string]any{"labels": map[string]any{"env": "prod"}},
		"levels":    map[string]any{"alerts": "rules"},
	})))
	levels := created["levels"].(map[string]any)
	if levels["proxies"] != "operate" || levels["alerts"] != "rules" || created["name"] != "Exploitation prod" {
		t.Fatalf("accès créé : %v", created)
	}
	id := created["id"].(string)

	listed, err := h.toolListTeamAccesses(r, map[string]any{"team": "ops"})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := json.Marshal(listed); !json.Valid(b) || len(listed.([]any)) != 1 {
		t.Fatalf("liste : %v", listed)
	}

	if _, err := h.toolSetTeamAccess(r, map[string]any{"team": "ops", "profile": "inconnu"}); err == nil {
		t.Fatal("profil inconnu")
	}
	if _, err := h.toolSetTeamAccess(r, map[string]any{"team": "ops", "levels": map[string]any{"snippets": "write"}}); err == nil {
		t.Fatal("l'écriture des objets partagés est refusée")
	}
	if _, err := h.toolSetTeamAccess(r, map[string]any{"team": "ops", "access": id, "name": "Renommé"}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.toolDeleteTeamAccess(r, map[string]any{"team": "ops", "access": id}); err != nil {
		t.Fatal(err)
	}
	if _, err := h.toolDeleteTeamAccess(r, map[string]any{"team": "ops", "access": id}); err == nil {
		t.Fatal("deuxième suppression")
	}
	if _, err := h.toolPreviewPerimeter(r, map[string]any{"perimeter": map[string]any{"proxy": "re:("}}); err == nil {
		t.Fatal("périmètre invalide")
	}
}

func mustTool(t *testing.T) func(any, error) any {
	return func(v any, err error) any {
		t.Helper()
		if err != nil {
			t.Fatal(err)
		}
		return v
	}
}
