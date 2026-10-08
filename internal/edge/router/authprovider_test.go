// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"testing"
)

// L'Admin pousse {"provider": …}, la passerelle écrit son cache avec {"type": …} : les deux doivent
// donner le même type.
func TestAuthProvider_AcceptsProviderAsTypeAlias(t *testing.T) {
	var fromAdmin, fromCache AuthProvider
	if err := json.Unmarshal([]byte(`{"id":"1","name":"n","provider":"ldap","config":{}}`), &fromAdmin); err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal([]byte(`{"id":"1","name":"n","type":"ldap","config":{}}`), &fromCache); err != nil {
		t.Fatal(err)
	}
	if fromAdmin.Type != "ldap" || fromCache.Type != "ldap" {
		t.Fatalf("types : admin=%q cache=%q", fromAdmin.Type, fromCache.Type)
	}
	b, _ := json.Marshal(fromAdmin) // le cache réécrit « type »
	var again AuthProvider
	_ = json.Unmarshal(b, &again)
	if again.Type != "ldap" || again.Name != "n" || again.ID != "1" {
		t.Fatalf("aller-retour : %+v", again)
	}
	var list []*AuthProvider
	if err := json.Unmarshal([]byte(`[{"id":"a","provider":"basic","config":{}},{"id":"b","type":"oidc","config":{}}]`), &list); err != nil || list[0].Type != "basic" || list[1].Type != "oidc" {
		t.Fatalf("liste : %v %v", list, err)
	}
}

func providerStoreWith(p *AuthProvider) *AuthProviderStore {
	s := NewAuthProviderStore()
	s.Replace([]*AuthProvider{p})
	return s
}

func TestResolveAuthProvider_ForcesEnabledAndFallsBackToType(t *testing.T) {
	store := providerStoreWith(&AuthProvider{ID: "p1", Name: "corp", Type: "ldap", Config: json.RawMessage(`{"ldap":{"url":"ldap://x"}}`)})
	got := ResolveAuthProvider(&Route{ID: "r", AuthProviderID: "p1"}, store)
	if got.SSO == nil || !got.SSO.Enabled || got.SSO.Provider != "ldap" || got.SSO.LDAP == nil {
		t.Fatalf("SSO = %+v", got.SSO)
	}
	// Résolution par nom (labels Docker).
	if got := ResolveAuthProvider(&Route{ID: "r", AuthProviderID: "corp"}, store); got.SSO == nil || !got.SSO.Enabled {
		t.Fatalf("résolution par nom : %+v", got.SSO)
	}
	// La route d'origine n'est pas modifiée.
	orig := &Route{ID: "r", AuthProviderID: "p1"}
	_ = ResolveAuthProvider(orig, store)
	if orig.SSO != nil {
		t.Fatal("la route d'origine a été modifiée")
	}
}

func TestResolveAuthProvider_ConfigEnabledFalseDoesNotDisableAuth(t *testing.T) {
	store := providerStoreWith(&AuthProvider{ID: "p1", Type: "basic", Config: json.RawMessage(`{"enabled":false,"basic_users":[{"username":"u","password":"p"}]}`)})
	if got := ResolveAuthProvider(&Route{AuthProviderID: "p1"}, store); !got.SSO.Enabled {
		t.Fatal("une route qui référence un fournisseur doit rester protégée")
	}
}

// Un fournisseur supprimé, désactivé ou illisible rendait la route publique.
func TestResolveAuthProvider_UnresolvableFailsClosed(t *testing.T) {
	store := providerStoreWith(&AuthProvider{ID: "bad", Type: "basic", Config: json.RawMessage(`not json`)})
	for name, id := range map[string]string{"introuvable": "gone", "config illisible": "bad"} {
		got := ResolveAuthProvider(&Route{AuthProviderID: id}, store)
		if got.SSO == nil || !got.SSO.Enabled || got.SSO.Provider != SSOProviderUnresolved {
			t.Errorf("%s : SSO = %+v", name, got.SSO)
		}
	}
}

func TestResolveAuthProvider_InlineSSOAndNoReferenceUntouched(t *testing.T) {
	store := NewAuthProviderStore()
	inline := &SSOConfig{Enabled: true, Provider: "basic"}
	r := &Route{AuthProviderID: "x", SSO: inline}
	if got := ResolveAuthProvider(r, store); got.SSO != inline {
		t.Fatal("la configuration SSO de la route doit l'emporter")
	}
	plain := &Route{ID: "r"}
	if got := ResolveAuthProvider(plain, store); got != plain || got.SSO != nil {
		t.Fatal("route sans fournisseur modifiée")
	}
}
