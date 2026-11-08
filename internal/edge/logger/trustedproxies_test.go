package logger

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestRealIPIgnoresHeadersFromUntrustedPeer(t *testing.T) {
	SetTrustedProxies(nil)
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:4242"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	req.Header.Set("CF-Connecting-IP", "5.6.7.8")
	if got := RealIP(req); got != "203.0.113.10" {
		t.Fatalf("RealIP = %q, want peer", got)
	}
}

func TestRealIPTrustsPrivateAndConfiguredPeers(t *testing.T) {
	SetTrustedProxies([]string{"203.0.113.0/24"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	for _, peer := range []string{"10.1.2.3:80", "127.0.0.1:80", "203.0.113.9:80"} {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = peer
		req.Header.Set("X-Forwarded-For", "1.2.3.4, 10.0.0.1")
		if got := RealIP(req); got != "1.2.3.4" {
			t.Fatalf("peer %s: RealIP = %q", peer, got)
		}
	}

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "198.51.100.1:80"
	req.Header.Set("X-Forwarded-For", "1.2.3.4")
	if got := RealIP(req); got != "198.51.100.1" {
		t.Fatalf("untrusted peer: RealIP = %q", got)
	}
}

func TestRealIPXFFReadFromRight(t *testing.T) {
	SetTrustedProxies([]string{"203.0.113.0/24"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	cases := map[string]string{
		"6.6.6.6, 1.2.3.4":                        "1.2.3.4",
		"6.6.6.6, 1.2.3.4, 203.0.113.7, 10.0.0.2": "1.2.3.4",
		"10.0.0.9, 203.0.113.7":                   "10.0.0.9",
		"garbage, 1.2.3.4":                        "1.2.3.4",
	}
	for xff, want := range cases {
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = "10.0.0.1:80"
		req.Header.Set("X-Forwarded-For", xff)
		if got := RealIP(req); got != want {
			t.Errorf("XFF %q: RealIP = %q, want %q", xff, got, want)
		}
	}
}

func TestRealIPWildcardKeepsLegacy(t *testing.T) {
	SetTrustedProxies([]string{"*"})
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "203.0.113.10:4242"
	req.Header.Set("X-Real-IP", "9.9.9.9")
	if got := RealIP(req); got != "9.9.9.9" {
		t.Fatalf("RealIP = %q", got)
	}
}

// Cloudflare Tunnel : cloudflared transmet CF-Connecting-IP et X-Forwarded-For. Sur la même machine ou le même réseau Docker, son
// adresse est privée donc crue par défaut ; ailleurs, elle doit être listée, sinon le visiteur prend l'adresse du tunnel.
func TestRealIPBehindCloudflareTunnel(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := func(peer string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer + ":51234"
		r.Header.Set("CF-Connecting-IP", "198.51.100.77")
		r.Header.Set("X-Forwarded-For", "198.51.100.77")
		return r
	}

	SetTrustedProxies(nil)
	for _, peer := range []string{"127.0.0.1", "172.18.0.4", "10.0.0.8"} {
		if got := RealIP(req(peer)); got != "198.51.100.77" {
			t.Errorf("cloudflared local %s : RealIP = %q", peer, got)
		}
	}
	if got := RealIP(req("203.0.113.40")); got != "203.0.113.40" {
		t.Errorf("cloudflared public non listé : RealIP = %q, attendu l'adresse du tunnel", got)
	}

	SetTrustedProxies([]string{"203.0.113.40"})
	if got := RealIP(req("203.0.113.40")); got != "198.51.100.77" {
		t.Errorf("cloudflared public listé : RealIP = %q", got)
	}

	// CF-Connecting-IP prime sur X-Forwarded-For, qu'un client peut avoir pré-rempli avant Cloudflare.
	r := req("172.18.0.4")
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.77")
	if got := RealIP(r); got != "198.51.100.77" {
		t.Errorf("CF-Connecting-IP doit primer : RealIP = %q", got)
	}

	SetTrustedProxies([]string{"none"})
	if got := RealIP(req("172.18.0.4")); got != "172.18.0.4" {
		t.Errorf("none : cloudflared privé n'est plus cru, RealIP = %q", got)
	}
}

// GPX_TRUSTED_PROXIES=none retire les défauts (loopback, réseaux privés) : sur un LAN dont les postes ne sont pas fiables,
// un poste ne choisit plus l'adresse que la passerelle lui attribue.
func TestTrustedProxiesNoneDropsPrivateDefaults(t *testing.T) {
	t.Cleanup(func() { SetTrustedProxies(nil) })

	req := func(peer string) *http.Request {
		r := httptest.NewRequest("GET", "/", nil)
		r.RemoteAddr = peer + ":4242"
		r.Header.Set("X-Forwarded-For", "1.2.3.4")
		r.Header.Set("X-Real-IP", "5.6.7.8")
		return r
	}

	SetTrustedProxies(nil)
	if got := RealIP(req("192.168.1.50")); got != "1.2.3.4" {
		t.Fatalf("par défaut un pair privé est cru, RealIP = %q", got)
	}

	SetTrustedProxies([]string{"none"})
	for _, peer := range []string{"192.168.1.50", "10.0.0.2", "172.20.0.3", "127.0.0.1", "203.0.113.9"} {
		if got := RealIP(req(peer)); got != peer {
			t.Errorf("none : pair %s, RealIP = %q, attendu l'adresse du pair", peer, got)
		}
	}

	SetTrustedProxies([]string{"none", "192.168.1.1", "10.9.0.0/16"})
	if got := RealIP(req("192.168.1.1")); got != "1.2.3.4" {
		t.Errorf("none + entrée explicite : pair listé, RealIP = %q", got)
	}
	if got := RealIP(req("10.9.4.4")); got != "1.2.3.4" {
		t.Errorf("none + CIDR explicite : pair du réseau listé, RealIP = %q", got)
	}
	if got := RealIP(req("192.168.1.50")); got != "192.168.1.50" {
		t.Errorf("none + entrée explicite : pair privé non listé, RealIP = %q", got)
	}

	SetTrustedProxies([]string{"NONE"})
	if got := RealIP(req("10.0.0.2")); got != "10.0.0.2" {
		t.Errorf("none insensible à la casse : RealIP = %q", got)
	}
}
