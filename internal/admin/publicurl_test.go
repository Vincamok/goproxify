// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func originFor(host, xfh, xfp string, tls bool) string {
	r := httptest.NewRequest(http.MethodGet, "/api/v1/me", nil)
	r.Host = host
	if xfh != "" {
		r.Header.Set("X-Forwarded-Host", xfh)
	}
	if xfp != "" {
		r.Header.Set("X-Forwarded-Proto", xfp)
	}
	if !tls {
		r.TLS = nil
	}
	return publicOriginFromRequest(r)
}

func TestPublicOriginFromRequest(t *testing.T) {
	cases := []struct {
		name, host, xfh, xfp, want string
	}{
		{"hôte simple", "admin.lan:9443", "", "", "http://admin.lan:9443"},
		{"derrière un proxy en https", "admin.lan:9443", "admin.example.fr", "https", "https://admin.example.fr"},
		{"plusieurs hôtes transmis : le premier", "admin.lan:9443", "admin.example.fr, relais.lan", "https", "https://admin.example.fr"},
		{"schéma exécutable refusé", "admin.lan:9443", "x.example/%0aalert(1)", "javascript", ""},
		{"schéma inconnu ignoré, schéma de la connexion utilisé", "admin.lan:9443", "", "gopher", "http://admin.lan:9443"},
		{"identifiants dans l'hôte", "admin.lan:9443", "pirate@evil.example", "https", ""},
		{"chemin dans l'hôte", "admin.lan:9443", "evil.example/x", "https", ""},
		{"requête dans l'hôte", "admin.lan:9443", "evil.example?x=1", "https", ""},
		{"espace dans l'hôte", "admin.lan:9443", "evil example", "https", ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if got := originFor(c.host, c.xfh, c.xfp, false); got != c.want {
				t.Fatalf("origine = %q, attendu %q", got, c.want)
			}
		})
	}
}

func TestCleanOrigin(t *testing.T) {
	good := map[string]string{
		"https://admin.example:9443":  "https://admin.example:9443",
		"https://admin.example:9443/": "https://admin.example:9443",
		" http://10.0.0.5:9443 ":      "http://10.0.0.5:9443",
		"https://example.fr/admin/":   "https://example.fr/admin",
	}
	for in, want := range good {
		if got := cleanOrigin(in); got != want {
			t.Errorf("cleanOrigin(%q) = %q, attendu %q", in, got, want)
		}
	}
	for _, bad := range []string{"", "admin.example", "javascript://x/%0aalert(1)", "ftp://x", "data:text/html,x",
		"https://u:p@admin.example", "https://admin.example/?a=1", "https://admin.example/#x", "https://"} {
		if got := cleanOrigin(bad); got != "" {
			t.Errorf("cleanOrigin(%q) = %q, attendu vide", bad, got)
		}
	}
}

// Les liens des pages d'erreur publiques ne reposent que sur ce que l'opérateur a déclaré : jamais sur l'en-tête d'une requête.
func TestErrorPageAdminURLIsOperatorDeclaredOnly(t *testing.T) {
	t.Setenv("GPX_ADMIN_PUBLIC_URL", "")
	if got := explicitAdminPublicURL(); got != "" {
		t.Fatalf("sans GPX_ADMIN_PUBLIC_URL, aucun lien attendu, obtenu %q", got)
	}
	t.Setenv("GPX_ADMIN_PUBLIC_URL", "https://admin.example.fr:9443/")
	if got := explicitAdminPublicURL(); got != "https://admin.example.fr:9443" {
		t.Fatalf("obtenu %q", got)
	}
	t.Setenv("GPX_ADMIN_PUBLIC_URL", "javascript://x/%0aalert(1)")
	if got := explicitAdminPublicURL(); got != "" {
		t.Fatalf("une valeur qui n'est pas une origine http(s) doit être ignorée, obtenu %q", got)
	}
}
