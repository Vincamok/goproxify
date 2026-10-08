// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"reflect"
	"strings"
	"testing"
)

// nestedManifest ressemble à un fournisseur d'authentification : un objet imbriqué, un secret dedans,
// une liste d'utilisateurs dont chacun porte un mot de passe.
var nestedManifest = Manifest{Type: "sso", Label: "SSO", Fields: []Field{
	{Key: "oidc.issuer_url", Label: "Issuer", Kind: KindText, Required: true},
	{Key: "oidc.client_secret", Label: "Secret", Kind: KindPassword, Secret: true, Required: true},
	{Key: "oidc.scopes", Label: "Scopes", Kind: KindList},
	{Key: "realm", Label: "Realm", Kind: KindText},
	{Key: "basic_users", Label: "Users", Kind: KindList, ItemKey: "username", ItemSecret: "password"},
}}

func TestNested_Validate(t *testing.T) {
	ok := map[string]any{"oidc": map[string]any{"issuer_url": "https://i", "client_secret": "s", "scopes": []any{"openid"}}, "realm": "r"}
	if err := nestedManifest.Validate(ok); err != nil {
		t.Fatal(err)
	}
	err := nestedManifest.Validate(map[string]any{"oidc": map[string]any{"issuer_url": "https://i"}})
	if err == nil || !strings.Contains(err.Error(), "oidc.client_secret") {
		t.Fatalf("champ imbriqué requis non signalé : %v", err)
	}
	err = nestedManifest.Validate(map[string]any{"oidc": map[string]any{"issuer_url": "i", "client_secret": "s", "client_secrt": "typo"}})
	if err == nil || !strings.Contains(err.Error(), "oidc.client_secrt") {
		t.Fatalf("clé imbriquée inconnue acceptée : %v", err)
	}
	err = nestedManifest.Validate(map[string]any{"oidc": map[string]any{"issuer_url": "i", "client_secret": "s"}, "autre": "x"})
	if err == nil || !strings.Contains(err.Error(), "autre") {
		t.Fatalf("clé inconnue de premier niveau acceptée : %v", err)
	}
}

func TestNested_MaskDoesNotMutateTheInput(t *testing.T) {
	in := map[string]any{
		"oidc":        map[string]any{"issuer_url": "https://i", "client_secret": "SECRET"},
		"basic_users": []any{map[string]any{"username": "alice", "password": "hunter2"}, map[string]any{"username": "bob", "password": ""}},
	}
	out := nestedManifest.Mask(in)
	if out["oidc"].(map[string]any)["client_secret"] != Masque || out["oidc"].(map[string]any)["issuer_url"] != "https://i" {
		t.Fatalf("oidc = %v", out["oidc"])
	}
	users := out["basic_users"].([]any)
	if users[0].(map[string]any)["password"] != Masque || users[0].(map[string]any)["username"] != "alice" {
		t.Fatalf("alice = %v", users[0])
	}
	if users[1].(map[string]any)["password"] != "" {
		t.Fatalf("mot de passe vide à ne pas masquer : %v", users[1])
	}
	if in["oidc"].(map[string]any)["client_secret"] != "SECRET" || in["basic_users"].([]any)[0].(map[string]any)["password"] != "hunter2" {
		t.Fatal("l'entrée a été modifiée")
	}
}

func TestNested_KeepSecrets(t *testing.T) {
	old := map[string]any{
		"oidc":        map[string]any{"issuer_url": "https://old", "client_secret": "KEEP"},
		"basic_users": []any{map[string]any{"username": "alice", "password": "pw-alice"}, map[string]any{"username": "bob", "password": "pw-bob"}},
	}
	next := map[string]any{
		"oidc": map[string]any{"issuer_url": "https://new", "client_secret": Masque},
		"basic_users": []any{
			map[string]any{"username": "bob", "password": Masque}, // réordonné : repris par nom, pas par rang
			map[string]any{"username": "alice", "password": "nouveau"},
			map[string]any{"username": "carol", "password": ""}, // nouvel utilisateur sans mot de passe
		},
	}
	got := nestedManifest.KeepSecrets(old, next)
	if got["oidc"].(map[string]any)["client_secret"] != "KEEP" || got["oidc"].(map[string]any)["issuer_url"] != "https://new" {
		t.Fatalf("oidc = %v", got["oidc"])
	}
	users := got["basic_users"].([]any)
	byName := map[string]any{}
	for _, u := range users {
		um := u.(map[string]any)
		byName[um["username"].(string)] = um["password"]
	}
	want := map[string]any{"bob": "pw-bob", "alice": "nouveau", "carol": nil}
	if !reflect.DeepEqual(byName, want) {
		t.Fatalf("mots de passe = %v, attendu %v", byName, want)
	}
	// Le masque n'est jamais stocké, même sans ancienne valeur.
	got = nestedManifest.KeepSecrets(nil, map[string]any{"oidc": map[string]any{"client_secret": Masque}})
	if _, ok := getPath(got, "oidc.client_secret"); ok {
		t.Fatalf("masque conservé : %v", got)
	}
	if next["oidc"].(map[string]any)["client_secret"] != Masque {
		t.Fatal("l'entrée a été modifiée")
	}
}

func TestPaths(t *testing.T) {
	cfg := map[string]any{}
	setPath(cfg, "a.b.c", 1)
	if v, ok := getPath(cfg, "a.b.c"); !ok || v != 1 {
		t.Fatalf("setPath/getPath : %v %v", v, ok)
	}
	delPath(cfg, "a.b.c")
	if len(cfg) != 0 {
		t.Fatalf("objets intermédiaires vides non retirés : %v", cfg)
	}
	if _, ok := getPath(cfg, "x.y"); ok {
		t.Fatal("chemin absent trouvé")
	}
	delPath(cfg, "x.y") // sans effet, sans panique
}

func TestCheck_ItemFieldsGoTogether(t *testing.T) {
	for name, f := range map[string]Field{
		"clé sans secret": {Key: "k", Label: "K", Kind: KindList, ItemKey: "id"},
		"secret sans clé": {Key: "k", Label: "K", Kind: KindList, ItemSecret: "pw"},
		"hors liste":      {Key: "k", Label: "K", Kind: KindText, ItemKey: "id", ItemSecret: "pw"},
	} {
		if err := (Manifest{Type: "x", Label: "X", Fields: []Field{f}}).check(); err == nil {
			t.Errorf("%s : manifeste invalide accepté", name)
		}
	}
}
