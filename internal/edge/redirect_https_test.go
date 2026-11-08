// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

func redirectGateway(t *testing.T, routes ...*router.Route) (*Server, *httptest.Server) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("backend")) }))
	t.Cleanup(backend.Close)
	for _, r := range routes {
		r.Type = router.RouteHTTP
		r.Backends = []router.Backend{{URL: backend.URL}}
	}
	s := newEphorGateway(t, t.TempDir(), routes...)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	s.certStore = edgetls.NewCertStore()
	t.Cleanup(func() { edgelog.SetTrustedProxies(nil) })
	return s, backend
}

func call(s *Server, method, url, peer string, secure bool, hdr map[string]string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, nil)
	req.RemoteAddr = peer + ":40000"
	if secure {
		req.TLS = &tls.ConnectionState{}
	}
	for k, v := range hdr {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	s.dispatch(rec, req)
	return rec
}

func TestRedirectHTTPSOnTLSRoute(t *testing.T) {
	s, _ := redirectGateway(t,
		&router.Route{ID: "r1", Host: "secure.test", TLSEnabled: true, RedirectHTTPS: true},
		&router.Route{ID: "r2", Host: "plain.test", TLSEnabled: true},
		&router.Route{ID: "r3", Host: "nots.test", RedirectHTTPS: true},
	)

	rec := call(s, http.MethodGet, "http://secure.test/a/b?x=1&y=%20z", "198.51.100.9", false, nil)
	if rec.Code != http.StatusPermanentRedirect {
		t.Fatalf("HTTP clair vers une route TLS avec redirection : %d, attendu 308", rec.Code)
	}
	if got := rec.Header().Get("Location"); got != "https://secure.test/a/b?x=1&y=%20z" {
		t.Fatalf("Location = %q", got)
	}
	if rec.Header().Get("Cache-Control") == "" {
		t.Error("une redirection permanente doit borner sa durée de cache")
	}
	if strings.Contains(rec.Body.String(), "backend") {
		t.Error("la requête ne doit pas atteindre le backend")
	}

	if rec := call(s, http.MethodPost, "http://secure.test/login", "198.51.100.9", false, nil); rec.Code != http.StatusPermanentRedirect {
		t.Errorf("POST : %d, attendu 308 (méthode et corps conservés)", rec.Code)
	}
	if rec := call(s, http.MethodGet, "https://secure.test/a", "198.51.100.9", true, nil); rec.Code != http.StatusOK || rec.Body.String() != "backend" {
		t.Errorf("en HTTPS la requête passe : %d %q", rec.Code, rec.Body.String())
	}
	if rec := call(s, http.MethodGet, "http://plain.test/a", "198.51.100.9", false, nil); rec.Code != http.StatusOK {
		t.Errorf("sans redirect_https le HTTP clair reste servi : %d", rec.Code)
	}
	if rec := call(s, http.MethodGet, "http://nots.test/a", "198.51.100.9", false, nil); rec.Code != http.StatusOK {
		t.Errorf("sans TLS sur la route il n'y a pas d'HTTPS où rediriger : %d", rec.Code)
	}
}

func TestRedirectHTTPSKeepsNonStandardPort(t *testing.T) {
	s, _ := redirectGateway(t, &router.Route{ID: "r1", Host: "secure.test", TLSEnabled: true, RedirectHTTPS: true})
	s.cfg.Network.HTTPSPort = 8443
	rec := call(s, http.MethodGet, "http://secure.test:8080/p?q=1", "198.51.100.9", false, nil)
	if got := rec.Header().Get("Location"); got != "https://secure.test:8443/p?q=1" {
		t.Fatalf("Location = %q", got)
	}
}

// Derrière un répartiteur qui termine le TLS, le trafic arrive en clair avec X-Forwarded-Proto: https : le croire (de lui seul)
// évite la boucle de redirections, mais un client quelconque ne peut pas s'en servir pour échapper à la redirection.
func TestRedirectHTTPSHonorsForwardedProtoOnlyFromTrustedPeers(t *testing.T) {
	s, _ := redirectGateway(t, &router.Route{ID: "r1", Host: "secure.test", TLSEnabled: true, RedirectHTTPS: true})
	hdr := map[string]string{"X-Forwarded-Proto": "https"}

	if rec := call(s, http.MethodGet, "http://secure.test/", "10.0.0.5", false, hdr); rec.Code != http.StatusOK {
		t.Errorf("répartiteur de confiance annonçant https : %d, attendu 200 (pas de boucle)", rec.Code)
	}
	if rec := call(s, http.MethodGet, "http://secure.test/", "198.51.100.9", false, hdr); rec.Code != http.StatusPermanentRedirect {
		t.Errorf("client public annonçant https : %d, attendu 308", rec.Code)
	}
	if rec := call(s, http.MethodGet, "http://secure.test/", "10.0.0.5", false, map[string]string{"X-Forwarded-Proto": "http"}); rec.Code != http.StatusPermanentRedirect {
		t.Errorf("répartiteur annonçant http : %d, attendu 308", rec.Code)
	}

	edgelog.SetTrustedProxies([]string{"none"})
	if rec := call(s, http.MethodGet, "http://secure.test/", "10.0.0.5", false, hdr); rec.Code != http.StatusPermanentRedirect {
		t.Errorf("avec GPX_TRUSTED_PROXIES=none un pair privé n'est plus cru : %d, attendu 308", rec.Code)
	}
}

// Cloudflare Tunnel vers le port HTTP de la passerelle : cloudflared pose X-Forwarded-Proto: https et CF-Connecting-IP. Depuis une
// adresse locale la requête passe sans boucle ; depuis une adresse publique non listée, le tunnel n'est pas cru.
func TestRedirectHTTPSBehindCloudflareTunnel(t *testing.T) {
	s, _ := redirectGateway(t, &router.Route{ID: "r1", Host: "secure.test", TLSEnabled: true, RedirectHTTPS: true})
	hdr := map[string]string{"X-Forwarded-Proto": "https", "CF-Connecting-IP": "198.51.100.77", "X-Forwarded-For": "198.51.100.77"}

	if rec := call(s, http.MethodGet, "http://secure.test/", "172.18.0.4", false, hdr); rec.Code != http.StatusOK {
		t.Errorf("cloudflared dans le réseau Docker : %d, attendu 200 (pas de boucle)", rec.Code)
	}
	if rec := call(s, http.MethodGet, "http://secure.test/", "203.0.113.40", false, hdr); rec.Code != http.StatusPermanentRedirect {
		t.Errorf("cloudflared public non listé : %d, attendu 308", rec.Code)
	}
	edgelog.SetTrustedProxies([]string{"203.0.113.40"})
	if rec := call(s, http.MethodGet, "http://secure.test/", "203.0.113.40", false, hdr); rec.Code != http.StatusOK {
		t.Errorf("cloudflared public listé dans GPX_TRUSTED_PROXIES : %d, attendu 200", rec.Code)
	}
}

// Le challenge http-01 doit rester joignable en clair : la redirection l'envoyait vers un HTTPS dont le certificat n'existe pas encore.
func TestACMEHTTP01IsServedBeforeRoutingAndRedirect(t *testing.T) {
	s, _ := redirectGateway(t, &router.Route{ID: "r1", Host: "secure.test", TLSEnabled: true, RedirectHTTPS: true})
	_ = s.certStore.Challenges.Apply(edgetls.ACMEChallenge{Type: edgetls.ChallengeHTTP01, Token: "tok", Response: "tok.thumb"})

	for _, host := range []string{"secure.test", "inconnu.test"} {
		rec := call(s, http.MethodGet, "http://"+host+"/.well-known/acme-challenge/tok", "198.51.100.9", false, nil)
		if rec.Code != http.StatusOK || rec.Body.String() != "tok.thumb" {
			t.Errorf("%s : %d %q, attendu la réponse du challenge", host, rec.Code, rec.Body.String())
		}
	}
	if rec := call(s, http.MethodGet, "http://secure.test/.well-known/acme-challenge/inconnu", "198.51.100.9", false, nil); rec.Code != http.StatusPermanentRedirect {
		t.Errorf("token inconnu : %d, attendu la redirection ordinaire", rec.Code)
	}
}
