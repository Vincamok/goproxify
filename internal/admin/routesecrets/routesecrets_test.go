// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package routesecrets

import (
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

const route = `{"host":"a.fr","auth":{"mode":"basic","basic_users":[{"username":"alice","password":"$2a$hash-a"},{"username":"bob","password":"pw-b"}],
"oidc":{"client_id":"id","client_secret":"CS","session_secret":"SS"},"ldap":{"url":"ldap://x","bind_password":"BP"}},
"bot":{"challenge_secret":"CH"},"signed_url":{"secret":"SU","paths":["/a"]},"request_headers":{"Authorization":"Bearer T","X-Env":"prod"},"plugins":[{"name":"geo","config":{"api_key":"PK","zone":"eu"}}]}`

func plugins(name string) (modules.Manifest, bool) {
	if name != "geo" {
		return modules.Manifest{}, false
	}
	return modules.Manifest{Type: "geo", Fields: []modules.Field{
		{Key: "api_key", Kind: modules.KindPassword, Secret: true}, {Key: "zone", Kind: modules.KindText},
	}}, true
}

func TestMask_HidesEverySecretAndKeepsTheRest(t *testing.T) {
	out := string(Mask([]byte(route), plugins))
	for _, s := range []string{"hash-a", "pw-b", `"CS"`, `"SS"`, `"BP"`, `"CH"`, `"SU"`, "Bearer T", `"PK"`} {
		if strings.Contains(out, s) {
			t.Errorf("secret %s présent : %s", s, out)
		}
	}
	for _, s := range []string{"alice", "bob", `"id"`, "ldap://x", "prod", `"eu"`, "/a"} {
		if !strings.Contains(out, s) {
			t.Errorf("valeur non secrète %s perdue : %s", s, out)
		}
	}
}

func TestKeep_RestoresMaskedSecretsAndAppliesChanges(t *testing.T) {
	masked := string(Mask([]byte(route), plugins))
	edited := strings.Replace(masked, `"a.fr"`, `"b.fr"`, 1)
	out, missing := Keep([]byte(route), []byte(edited), plugins)
	if len(missing) != 0 {
		t.Fatalf("manquants : %v", missing)
	}
	s := string(out)
	for _, v := range []string{"hash-a", "pw-b", `"CS"`, `"SS"`, `"BP"`, `"CH"`, `"SU"`, "Bearer T", `"PK"`, `"b.fr"`} {
		if !strings.Contains(s, v) {
			t.Errorf("%s perdu : %s", v, s)
		}
	}
	if strings.Contains(s, modules.Masque) {
		t.Errorf("masque enregistré : %s", s)
	}
}

func TestKeep_RetypedSecretWinsAndRenamedUserNeedsRetyping(t *testing.T) {
	masked := Mask([]byte(route), plugins)
	retyped := strings.Replace(string(masked), `"challenge_secret":"••••••••"`, `"challenge_secret":"NEW"`, 1)
	out, missing := Keep([]byte(route), []byte(retyped), plugins)
	if len(missing) != 0 || !strings.Contains(string(out), `"NEW"`) {
		t.Errorf("secret retapé : %v %s", missing, out)
	}
	renamed := strings.Replace(string(masked), `"username":"bob"`, `"username":"robert"`, 1)
	_, missing = Keep([]byte(route), []byte(renamed), plugins)
	if len(missing) != 1 || !strings.Contains(missing[0], "password") {
		t.Errorf("utilisateur renommé : manquants = %v", missing)
	}
}

func TestKeep_MaskWithoutOriginIsReportedAndNeverStored(t *testing.T) {
	out, missing := Keep(nil, []byte(`{"bot":{"challenge_secret":"••••••••"},"plugins":[{"name":"geo","config":{"api_key":"••••••••"}}]}`), plugins)
	if len(missing) != 2 || strings.Contains(string(out), modules.Masque) {
		t.Errorf("manquants = %v, sortie = %s", missing, out)
	}
}

func TestMask_EmptyAndUnreadable(t *testing.T) {
	if got := string(Mask([]byte(`{"bot":{"challenge_secret":""}}`), nil)); strings.Contains(got, modules.Masque) {
		t.Errorf("secret vide masqué : %s", got)
	}
	if string(Mask([]byte("pas du json"), nil)) != "pas du json" {
		t.Error("valeur illisible modifiée")
	}
}
