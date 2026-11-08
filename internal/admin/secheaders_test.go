// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func serveWith(t *testing.T, path string, secure bool, inner http.HandlerFunc) http.Header {
	t.Helper()
	req := httptest.NewRequest(http.MethodGet, path, nil)
	if secure {
		req.TLS = &tls.ConnectionState{}
	}
	rec := httptest.NewRecorder()
	securityHeaders(inner).ServeHTTP(rec, req)
	return rec.Header()
}

func TestSecurityHeadersOnEveryResponse(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }
	for _, path := range []string{"/", "/index.html", "/api/v1/health", "/api/v1/proxies", "/api-docs", "/mcp"} {
		h := serveWith(t, path, false, ok)
		if h.Get("X-Content-Type-Options") != "nosniff" {
			t.Errorf("%s : X-Content-Type-Options = %q", path, h.Get("X-Content-Type-Options"))
		}
		if h.Get("X-Frame-Options") != "DENY" {
			t.Errorf("%s : X-Frame-Options = %q", path, h.Get("X-Frame-Options"))
		}
		csp := h.Get("Content-Security-Policy")
		for _, want := range []string{"frame-ancestors 'none'", "base-uri 'self'", "object-src 'none'"} {
			if !strings.Contains(csp, want) {
				t.Errorf("%s : CSP %q sans %q", path, csp, want)
			}
		}
		if h.Get("Referrer-Policy") != "same-origin" {
			t.Errorf("%s : Referrer-Policy = %q", path, h.Get("Referrer-Policy"))
		}
		if !strings.Contains(h.Get("Permissions-Policy"), "camera=()") {
			t.Errorf("%s : Permissions-Policy = %q", path, h.Get("Permissions-Policy"))
		}
	}
}

// Une directive de script ou de style casserait l'interface (1 100 gestionnaires d'événements et des milliers de style=
// en ligne) : la politique se limite à ce qui ne dépend pas du code de la page.
func TestAdminCSPDoesNotRestrictScriptsOrStyles(t *testing.T) {
	csp := serveWith(t, "/", false, func(w http.ResponseWriter, r *http.Request) {}).Get("Content-Security-Policy")
	for _, directive := range []string{"default-src", "script-src", "style-src", "connect-src", "img-src", "form-action"} {
		if strings.Contains(csp, directive) {
			t.Errorf("la politique ne doit pas poser %s : %q", directive, csp)
		}
	}
}

func TestSecurityHeadersHSTSOnlyOverTLS(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {}
	if got := serveWith(t, "/", false, ok).Get("Strict-Transport-Security"); got != "" {
		t.Errorf("HSTS en HTTP clair : %q", got)
	}
	if got := serveWith(t, "/", true, ok).Get("Strict-Transport-Security"); !strings.Contains(got, "max-age=31536000") {
		t.Errorf("HSTS en HTTPS : %q", got)
	}
}

func TestSecurityHeadersAPIResponsesAreNotCached(t *testing.T) {
	ok := func(w http.ResponseWriter, r *http.Request) {}
	if got := serveWith(t, "/api/v1/users", false, ok).Get("Cache-Control"); got != "no-store" {
		t.Errorf("API : Cache-Control = %q", got)
	}
	if got := serveWith(t, "/js/app.js", false, ok).Get("Cache-Control"); got != "" {
		t.Errorf("les ressources statiques gardent leur politique de cache, obtenu %q", got)
	}
}

// Un gestionnaire qui pose lui-même un en-tête (cache d'un export, politique propre à une page) garde la main.
func TestSecurityHeadersDoNotOverrideHandlers(t *testing.T) {
	h := serveWith(t, "/api/v1/export", false, func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Cache-Control", "private, max-age=60")
		w.Header().Set("Content-Security-Policy", "default-src 'none'")
	})
	if h.Get("Cache-Control") != "private, max-age=60" || h.Get("Content-Security-Policy") != "default-src 'none'" {
		t.Errorf("en-têtes du gestionnaire écrasés : %v", h)
	}
}
