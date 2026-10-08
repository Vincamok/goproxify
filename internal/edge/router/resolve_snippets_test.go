// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"testing"
)

func snippetStore(list ...*Snippet) *SnippetStore {
	s := NewSnippetStore()
	s.Replace(list)
	return s
}

func TestResolveSnippets_UnresolvedSecuritySnippetsAreReported(t *testing.T) {
	good := &Snippet{ID: "ok", Name: "ok", Type: SnippetIPFilter, Config: json.RawMessage(`{"mode":"deny","cidrs":["10.0.0.0/8"]}`)}
	badIP := &Snippet{ID: "bad", Name: "bad", Type: SnippetIPFilter, Config: json.RawMessage(`{"mode":"deny","cidrs":"10.0.0.0/8"}`)}
	badWAF := &Snippet{ID: "badwaf", Name: "badwaf", Type: SnippetWAF, Config: json.RawMessage(`[1]`)}
	cors := &Snippet{ID: "cors", Name: "cors", Type: SnippetCORS, Config: json.RawMessage(`"x"`)}
	store := snippetStore(good, badIP, badWAF, cors)

	if r := ResolveSnippets(&Route{SnippetIDs: []string{"ok"}}, store); r.SnippetUnresolved != "" || r.IPFilter == nil {
		t.Errorf("snippet valide : unresolved=%q ipfilter=%v", r.SnippetUnresolved, r.IPFilter)
	}
	for name, ids := range map[string][]string{
		"introuvable":         {"nope"},
		"filtre IP illisible": {"bad"},
		"WAF illisible":       {"badwaf"},
		"un bon, un absent":   {"ok", "nope"},
	} {
		if r := ResolveSnippets(&Route{SnippetIDs: ids}, store); r.SnippetUnresolved == "" {
			t.Errorf("%s : non signalé", name)
		}
	}
	// Les types sans enjeu de détection gardent leur comportement : illisible ⇒ ignoré.
	if r := ResolveSnippets(&Route{SnippetIDs: []string{"cors"}}, store); r.SnippetUnresolved != "" {
		t.Errorf("cors : %q", r.SnippetUnresolved)
	}
	// Une route sans snippet n'est jamais bloquée.
	if r := ResolveSnippets(&Route{}, store); r.SnippetUnresolved != "" {
		t.Error("route sans snippet")
	}
}

func TestRoute_SnippetUnresolvedIsNeverSerialized(t *testing.T) {
	b, _ := json.Marshal(Route{SnippetUnresolved: "x"})
	var m map[string]any
	_ = json.Unmarshal(b, &m)
	if _, ok := m["SnippetUnresolved"]; ok {
		t.Fatalf("sérialisé : %s", b)
	}
}
