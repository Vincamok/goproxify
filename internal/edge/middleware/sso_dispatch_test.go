// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Caractérisation de l'aiguillage SSO. Ce fichier a précédé la migration vers le registre de modules :
// pour chaque nom de fournisseur, une requête sans identifiants doit produire la même réponse qu'avant.

const sessionSecret = "0123456789abcdef0123456789abcdef"

func ssoBackend() http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Seen-User", r.Header.Get("X-Remote-User"))
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("BACKEND"))
	})
}

func fullSSO(provider string) *router.SSOConfig {
	return &router.SSOConfig{
		Enabled: true, Provider: provider,
		OIDC:   &router.OIDCConfig{IssuerURL: "http://127.0.0.1:1", ClientID: "c", ClientSecret: "s", RedirectURL: "http://app/cb", SessionSecret: sessionSecret},
		GitHub: &router.GitHubOAuthConfig{ClientID: "c", ClientSecret: "s", RedirectURL: "http://app/cb", SessionSecret: sessionSecret},
		LDAP:   &router.LDAPConfig{URL: "ldap://127.0.0.1:1", BaseDN: "dc=x", UserFilter: "(uid=%s)", SessionSecret: sessionSecret},
		SAML:   &router.SAMLConfig{EntityID: "http://app/meta", ACSPath: "/saml/acs", SessionSecret: sessionSecret},
		// Aucun service d'authentification n'écoute ici.
		ForwardAuthURL: "http://127.0.0.1:1/auth",
		BasicUsers:     []router.BasicUser{{Username: "u", Password: "p"}},
	}
}

func doGet(h http.Handler, headers map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.fr/secret", nil)
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

// Aucun fournisseur connu ne laisse passer une requête sans identifiants.
func TestSSOAuth_KnownProvidersRejectAnonymousRequests(t *testing.T) {
	want := map[string]int{
		"oidc": http.StatusFound, "pocket_id": http.StatusFound, "google": http.StatusFound, "microsoft": http.StatusFound,
		"entra": http.StatusFound, "auth0": http.StatusFound, "okta": http.StatusFound, "keycloak": http.StatusFound,
		"zitadel": http.StatusFound, "casdoor": http.StatusFound, "dex": http.StatusFound,
		"github": http.StatusFound,
		"ldap":   http.StatusUnauthorized, "ldap_ad": http.StatusUnauthorized,
		"saml":    http.StatusInternalServerError, // métadonnées de test volontairement incomplètes
		"basic":   http.StatusUnauthorized,
		"forward": http.StatusBadGateway, "authentik": http.StatusBadGateway, "authelia": http.StatusBadGateway, "oauth2_proxy": http.StatusBadGateway,
	}
	for provider, code := range want {
		rec := doGet(SSOAuth(fullSSO(provider))(ssoBackend()), nil)
		if rec.Code != code {
			t.Errorf("%s : code %d, attendu %d", provider, rec.Code, code)
		}
		if rec.Body.String() == "BACKEND" {
			t.Errorf("%s : requête anonyme transmise au backend", provider)
		}
	}
}

func TestSSOAuth_DisabledOrNilPassesThrough(t *testing.T) {
	for _, cfg := range []*router.SSOConfig{nil, {Enabled: false, Provider: "basic"}} {
		if rec := doGet(SSOAuth(cfg)(ssoBackend()), nil); rec.Body.String() != "BACKEND" {
			t.Errorf("config %+v : %d", cfg, rec.Code)
		}
	}
}

func TestSSOAuth_BasicAcceptsValidCredentials(t *testing.T) {
	h := SSOAuth(fullSSO("basic"))(ssoBackend())
	rec := doGet(h, map[string]string{"Authorization": "Basic dTpw"}) // u:p
	if rec.Code != 200 || rec.Header().Get("X-Seen-User") != "u" {
		t.Fatalf("code %d, utilisateur %q", rec.Code, rec.Header().Get("X-Seen-User"))
	}
	if rec := doGet(h, map[string]string{"Authorization": "Basic dTp4"}); rec.Code != http.StatusUnauthorized { // u:x
		t.Fatalf("mauvais mot de passe : %d", rec.Code)
	}
	if rec := doGet(h, nil); rec.Header().Get("WWW-Authenticate") == "" {
		t.Fatal("WWW-Authenticate absent")
	}
}

func TestSSOAuth_ForwardAuthAllowsWhenServiceAccepts(t *testing.T) {
	auth := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("Authorization") == "Bearer good" {
			w.Header().Set("Remote-User", "alice")
			return
		}
		w.WriteHeader(http.StatusUnauthorized)
	}))
	defer auth.Close()
	cfg := fullSSO("forward")
	cfg.ForwardAuthURL = auth.URL
	h := SSOAuth(cfg)(ssoBackend())
	if rec := doGet(h, map[string]string{"Authorization": "Bearer good"}); rec.Body.String() != "BACKEND" {
		t.Fatalf("accès légitime refusé : %d", rec.Code)
	}
	if rec := doGet(h, nil); rec.Code != http.StatusUnauthorized {
		t.Fatalf("accès anonyme : %d", rec.Code)
	}
}
