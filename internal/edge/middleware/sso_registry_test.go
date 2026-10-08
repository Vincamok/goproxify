// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestSSORegistry_ProviderNamesAndOrder(t *testing.T) {
	var got []string
	for _, m := range SSOProviders() {
		got = append(got, m.Type)
	}
	want := []string{
		"forward", "authentik", "authelia", "oauth2_proxy", "basic",
		"oidc", "pocket_id", "google", "microsoft", "entra", "auth0", "okta", "keycloak", "zitadel", "casdoor", "dex",
		"github", "ldap", "ldap_ad", "saml",
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("fournisseurs = %v", got)
	}
}

// Tous les noms que l'ancien aiguillage acceptait sont dans le registre (sinon ils tomberaient en 503).
func TestSSORegistry_CoversEveryProviderTheOldSwitchKnew(t *testing.T) {
	for _, name := range []string{"authentik", "authelia", "oauth2_proxy", "forward", "basic", "github", "ldap", "ldap_ad", "saml",
		"pocket_id", "oidc", "google", "microsoft", "entra", "auth0", "okta", "keycloak", "zitadel", "casdoor", "dex"} {
		if _, ok := SSOProviderManifest(name); !ok {
			t.Errorf("%s absent du registre", name)
		}
	}
}

// Un secret ne doit jamais rester déclaré en clair : tout secret du manifeste est un mot de passe.
func TestSSORegistry_SecretFields(t *testing.T) {
	want := map[string][]string{
		"oidc": {"oidc.client_secret", "oidc.session_secret"}, "github": {"github.client_secret", "github.session_secret"},
		"ldap": {"ldap.bind_password", "ldap.session_secret"}, "saml": {"saml.key_pem", "saml.session_secret"},
		"forward": nil, "basic": nil,
	}
	for typ, keys := range want {
		m, _ := SSOProviderManifest(typ)
		var secrets []string
		for _, f := range m.Fields {
			if f.Secret {
				secrets = append(secrets, f.Key)
			}
		}
		if !reflect.DeepEqual(secrets, keys) {
			t.Errorf("%s : secrets = %v, attendu %v", typ, secrets, keys)
		}
	}
	basic, _ := SSOProviderManifest("basic")
	if basic.Fields[1].ItemSecret != "password" || basic.Fields[1].ItemKey != "username" {
		t.Errorf("basic_users : %+v", basic.Fields[1])
	}
}

// Un fournisseur inconnu, vide, ou dont la section est absente laissait passer sans authentification.
func TestSSOAuth_FailsClosed(t *testing.T) {
	cases := map[string]*router.SSOConfig{
		"nom inconnu":            {Enabled: true, Provider: "ldpa"},
		"nom vide":               {Enabled: true, Provider: ""},
		"oidc sans section":      {Enabled: true, Provider: "oidc"},
		"preset sans section":    {Enabled: true, Provider: "google"},
		"github sans section":    {Enabled: true, Provider: "github"},
		"ldap sans section":      {Enabled: true, Provider: "ldap"},
		"ldap_ad sans section":   {Enabled: true, Provider: "ldap_ad"},
		"saml sans section":      {Enabled: true, Provider: "saml"},
		"forward sans URL":       {Enabled: true, Provider: "forward"},
		"authelia sans URL":      {Enabled: true, Provider: "authelia"},
		"basic sans utilisateur": {Enabled: true, Provider: "basic"},
	}
	for name, cfg := range cases {
		rec := doGet(SSOAuth(cfg)(ssoBackend()), nil)
		if rec.Code != http.StatusServiceUnavailable || rec.Body.String() == "BACKEND" {
			t.Errorf("%s : code %d corps %q (attendu 503, backend jamais atteint)", name, rec.Code, rec.Body.String())
		}
	}
}

// Une clé HMAC vide laissait n'importe qui fabriquer un cookie de session valide. Avec un secret de
// session vide, un secret aléatoire est utilisé : le cookie forgé avec la clé vide est refusé.
func TestSSOAuth_EmptySessionSecretCannotBeForged(t *testing.T) {
	cfg := fullSSO("ldap")
	cfg.LDAP.SessionSecret = ""
	h := SSOAuth(cfg)(ssoBackend())

	// Cookie de session LDAP signé avec la clé vide, tel que ldapSessionSet l'écrirait.
	w := httptest.NewRecorder()
	ldapSessionSet(w, httptest.NewRequest(http.MethodGet, "http://app.example.fr/", nil), "", "admin", "Admin", "a@x", 3600)
	cookies := w.Result().Cookies()
	if len(cookies) == 0 {
		t.Fatal("cookie de test non produit")
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.example.fr/secret", nil)
	req.AddCookie(cookies[0])
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Body.String() == "BACKEND" {
		t.Fatal("cookie forgé avec une clé HMAC vide accepté")
	}
}

func TestSessionSecretOrRandom(t *testing.T) {
	if got := sessionSecretOrRandom("x", "configured"); got != "configured" {
		t.Fatalf("secret configuré modifié : %q", got)
	}
	a, b := sessionSecretOrRandom("x", ""), sessionSecretOrRandom("x", "  ")
	if len(a) != 64 || len(b) != 64 || a == b {
		t.Fatalf("secrets aléatoires attendus distincts de 64 caractères : %q %q", a, b)
	}
}

// Le Basic Auth du proxy ne comparait qu'en texte clair alors que la configuration documente bcrypt :
// un mot de passe bcrypt ne pouvait jamais se connecter. Un mot de passe enregistré vide laissait aussi
// entrer avec un mot de passe vide.
func TestBasicAuth_BcryptConstantTimeAndEmptyPassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("s3cret"), bcrypt.MinCost)
	cfg := &router.SSOConfig{Enabled: true, Provider: "basic", BasicUsers: []router.BasicUser{
		{Username: "hashed", Password: string(hash)},
		{Username: "legacy", Password: "plain"},
		{Username: "empty", Password: ""},
	}}
	h := SSOAuth(cfg)(ssoBackend())
	basic := func(u, p string) map[string]string {
		req := httptest.NewRequest(http.MethodGet, "/", nil)
		req.SetBasicAuth(u, p)
		return map[string]string{"Authorization": req.Header.Get("Authorization")}
	}
	for _, c := range []struct {
		user, pass string
		want       int
	}{
		{"hashed", "s3cret", 200}, {"hashed", "wrong", 401}, {"hashed", string(hash), 401},
		{"legacy", "plain", 200}, {"legacy", "Plain", 401},
		{"empty", "", 401}, {"empty", "x", 401},
		{"ghost", "s3cret", 401},
	} {
		if rec := doGet(h, basic(c.user, c.pass)); rec.Code != c.want {
			t.Errorf("%s/%q : code %d, attendu %d", c.user, c.pass, rec.Code, c.want)
		}
	}
}

func TestMatchBasicPassword(t *testing.T) {
	hash, _ := bcrypt.GenerateFromPassword([]byte("pw"), bcrypt.MinCost)
	for _, c := range []struct {
		stored, given string
		want          bool
	}{
		{string(hash), "pw", true}, {string(hash), "no", false},
		{"plain", "plain", true}, {" plain ", "plain", true}, {"plain", "Plain", false},
		{"", "", false}, {"   ", "", false},
		{"$2y$notahash", "x", false},
	} {
		if got := MatchBasicPassword(c.stored, c.given); got != c.want {
			t.Errorf("MatchBasicPassword(%.12q, %q) = %v", c.stored, c.given, got)
		}
	}
}

// Les préréglages OIDC fournissent l'URL de l'émetteur quand la configuration l'omet, sans modifier
// la configuration partagée (le middleware travaille sur une copie).
func TestOIDCPresetIssuerIsAppliedOnACopy(t *testing.T) {
	cfg := fullSSO("google")
	cfg.OIDC.IssuerURL = ""
	h := SSOAuth(cfg)(ssoBackend())
	_ = h
	if cfg.OIDC.IssuerURL != "" {
		t.Fatalf("la configuration partagée a été modifiée : %q", cfg.OIDC.IssuerURL)
	}
}

func TestSSOAuth_UnresolvedProviderIsAnExplicitRefusal(t *testing.T) {
	rec := doGet(SSOAuth(&router.SSOConfig{Enabled: true, Provider: router.SSOProviderUnresolved})(ssoBackend()), nil)
	if rec.Code != http.StatusServiceUnavailable || !strings.Contains(rec.Body.String(), "introuvable") {
		t.Fatalf("code %d corps %q", rec.Code, rec.Body.String())
	}
}
