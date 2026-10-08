// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"reflect"
	"strings"
	"testing"
)

var testManifest = Manifest{
	Type: "demo", Label: "Demo",
	Fields: []Field{
		{Key: "url", Label: "URL", Kind: KindText, Required: true},
		{Key: "token", Label: "Token", Kind: KindPassword, Secret: true, Required: true},
		{Key: "to", Label: "To", Kind: KindList},
	},
}

func TestRegistry_RegisterLookupOrder(t *testing.T) {
	r := NewRegistry[func() string]()
	r.Register(Manifest{Type: "b", Label: "B"}, func() string { return "b" })
	r.Register(Manifest{Type: "a", Label: "A"}, func() string { return "a" })

	f, m, ok := r.Lookup("a")
	if !ok || f() != "a" || m.Label != "A" {
		t.Fatal("lookup a")
	}
	if _, _, ok := r.Lookup("zz"); ok {
		t.Fatal("type inconnu trouvé")
	}
	var order []string
	for _, m := range r.Manifests() {
		order = append(order, m.Type)
	}
	if !reflect.DeepEqual(order, []string{"b", "a"}) {
		t.Fatalf("ordre d'enregistrement perdu : %v", order)
	}
	if !reflect.DeepEqual(r.Types(), []string{"a", "b"}) {
		t.Fatalf("Types() doit être trié : %v", r.Types())
	}
}

func TestRegistry_RegisterPanicsOnMistakes(t *testing.T) {
	r := NewRegistry[int]()
	r.Register(Manifest{Type: "a", Label: "A"}, 1)
	for name, m := range map[string]Manifest{
		"doublon":         {Type: "a", Label: "A"},
		"sans libellé":    {Type: "x"},
		"champ en double": {Type: "x", Label: "X", Fields: []Field{{Key: "k", Label: "K", Kind: KindText}, {Key: "k", Label: "K", Kind: KindText}}},
		"genre inconnu":   {Type: "x", Label: "X", Fields: []Field{{Key: "k", Label: "K", Kind: "blob"}}},
		"secret en clair": {Type: "x", Label: "X", Fields: []Field{{Key: "k", Label: "K", Kind: KindText, Secret: true}}},
	} {
		func() {
			defer func() {
				if recover() == nil {
					t.Errorf("%s : pas de panique", name)
				}
			}()
			r.Register(m, 1)
		}()
	}
}

func TestManifest_Validate(t *testing.T) {
	if err := testManifest.Validate(map[string]any{"url": "u", "token": "t"}); err != nil {
		t.Fatal(err)
	}
	err := testManifest.Validate(map[string]any{"url": " ", "to": []any{}})
	if err == nil || !strings.Contains(err.Error(), "url") || !strings.Contains(err.Error(), "token") {
		t.Fatalf("champs requis non signalés : %v", err)
	}
	err = testManifest.Validate(map[string]any{"url": "u", "token": "t", "typo": 1})
	if err == nil || !strings.Contains(err.Error(), "typo") {
		t.Fatalf("clé inconnue acceptée : %v", err)
	}
}

func TestManifest_Mask(t *testing.T) {
	got := testManifest.Mask(map[string]any{"url": "u", "token": "secret", "to": []any{"a"}})
	if got["token"] != Masque || got["url"] != "u" {
		t.Fatalf("masquage : %v", got)
	}
	if got := testManifest.Mask(map[string]any{"token": ""}); got["token"] != "" {
		t.Fatal("un secret vide ne doit pas être masqué (rien à cacher)")
	}
}

func TestManifest_KeepSecrets(t *testing.T) {
	old := map[string]any{"url": "old", "token": "keep-me"}
	for name, next := range map[string]map[string]any{
		"absent":  {"url": "new"},
		"vide":    {"url": "new", "token": ""},
		"masqué":  {"url": "new", "token": Masque},
		"espaces": {"url": "new", "token": "  "},
	} {
		got := testManifest.KeepSecrets(old, next)
		if got["token"] != "keep-me" || got["url"] != "new" {
			t.Errorf("%s : %v", name, got)
		}
	}
	if got := testManifest.KeepSecrets(old, map[string]any{"token": "fresh"}); got["token"] != "fresh" {
		t.Fatalf("nouveau secret écrasé : %v", got)
	}
	if got := testManifest.KeepSecrets(nil, map[string]any{"token": Masque}); got["token"] != nil {
		t.Fatalf("le masque ne doit jamais être stocké comme secret : %v", got)
	}
}
