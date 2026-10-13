// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/waf"
)

// Caractérisation de l'ordre d'exécution de la chaîne d'une route : écrite contre l'assemblage câblé à la main, puis
// conservée quand le registre des détecteurs a pris en charge la construction (ADR 0007). L'ordre n'est pas
// cosmétique : le WAF juge avant le filtre IP, le débit coupe avant lui, etc. Chaque test place deux étapes qui
// refuseraient la même requête et regarde laquelle l'a refusée.

func orderServer(t *testing.T) (*Server, *httptest.Server) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(http.StatusOK) }))
	t.Cleanup(backend.Close)
	s := testEdgeServer()
	s.health = proxy.NewBackendHealth(s.log.Logger())
	s.wafEngine = waf.NewEngine(&router.WAFConfig{Enabled: true, Mode: "block"}, s.log.Logger())
	return s, backend
}

func blocked(host, stage string) float64 {
	var total float64
	for _, reason := range []string{"in_denylist", "not_in_allowlist", "rate_exceeded", "quota_exceeded", "ua_blacklist", "js_challenge", "challenge_failed", "invalid_mode", "db_unavailable"} {
		total += testutil.ToFloat64(metrics.Pipeline.BlockedTotal.WithLabelValues(host, stage, reason))
	}
	return total
}

func send(s *Server, route *router.Route, path, ip, ua string) int {
	req := httptest.NewRequest(http.MethodGet, "http://"+route.Host+path, nil)
	req.RemoteAddr = ip + ":5000"
	if ua != "" {
		req.Header.Set("User-Agent", ua)
	}
	rr := httptest.NewRecorder()
	s.handlerForRoute(route, "").ServeHTTP(rr, req)
	return rr.Code
}

const sqli = "/?id=1%20UNION%20SELECT%20username,password%20FROM%20users--"

func TestDispatchOrder_WAFBeforeIPFilter(t *testing.T) {
	s, backend := orderServer(t)
	route := &router.Route{ID: "ord-waf-ip", Host: "ord-waf-ip.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		WAF:      &router.WAFConfig{Enabled: true, Mode: "block"},
		IPFilter: &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"203.0.113.0/24"}}}

	if code := send(s, route, sqli, "203.0.113.5", ""); code != http.StatusForbidden {
		t.Fatalf("requête piégée : %d", code)
	}
	if n := blocked(route.Host, "ipfilter"); n != 0 {
		t.Fatalf("le WAF doit juger avant le filtre IP : le filtre IP a refusé %v fois", n)
	}
	if code := send(s, route, "/", "203.0.113.5", ""); code != http.StatusForbidden {
		t.Fatalf("requête saine d'une IP interdite : %d", code)
	}
	if n := blocked(route.Host, "ipfilter"); n != 1 {
		t.Fatalf("sans charge utile, le filtre IP refuse : %v", n)
	}
}

func TestDispatchOrder_RateLimitBeforeIPFilter(t *testing.T) {
	s, backend := orderServer(t)
	route := &router.Route{ID: "ord-rl-ip", Host: "ord-rl-ip.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		RateLimit: &router.RateLimitConfig{RequestsPerSecond: 0.001, Burst: 1},
		IPFilter:  &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"203.0.113.0/24"}}}

	send(s, route, "/", "203.0.113.6", "") // consomme l'unique jeton, puis le filtre IP refuse
	if n := blocked(route.Host, "ipfilter"); n != 1 {
		t.Fatalf("première requête : filtre IP %v", n)
	}
	send(s, route, "/", "203.0.113.6", "") // le débit coupe avant que le filtre IP ne soit consulté
	if rl, ip := blocked(route.Host, "ratelimit"), blocked(route.Host, "ipfilter"); rl != 1 || ip != 1 {
		t.Fatalf("deuxième requête : ratelimit=%v ipfilter=%v, attendu 1 et 1", rl, ip)
	}
}

func TestDispatchOrder_BotBeforeRateLimit(t *testing.T) {
	s, backend := orderServer(t)
	route := &router.Route{ID: "ord-bot-rl", Host: "ord-bot-rl.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		Bot:       &router.BotConfig{Enabled: true, Mode: "block", UABlacklist: []string{"badbot"}},
		RateLimit: &router.RateLimitConfig{RequestsPerSecond: 0.001, Burst: 1}}

	send(s, route, "/", "203.0.113.7", "badbot/1.0")
	send(s, route, "/", "203.0.113.7", "badbot/1.0")
	if bot, rl := blocked(route.Host, "bot"), blocked(route.Host, "ratelimit"); bot != 2 || rl != 0 {
		t.Fatalf("le bot doit refuser avant le débit : bot=%v ratelimit=%v, attendu 2 et 0", bot, rl)
	}
}

func TestDispatchOrder_IPFilterBeforePlugins(t *testing.T) {
	s, backend := orderServer(t)
	// Un plugin absent refuse la route (503) : si le filtre IP juge avant lui, une IP interdite reçoit 403, pas 503.
	route := &router.Route{ID: "ord-ip-plug", Host: "ord-ip-plug.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		IPFilter: &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"203.0.113.0/24"}},
		Plugins:  []router.PluginRef{{Name: "absent"}}}

	if code := send(s, route, "/", "203.0.113.8", ""); code != http.StatusForbidden {
		t.Fatalf("IP interdite : %d, le filtre IP doit juger avant les plugins", code)
	}
	if code := send(s, route, "/", "198.51.100.8", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("IP autorisée : %d, le plugin absent doit refuser (fail-closed)", code)
	}
}

func TestDispatchOrder_PluginsBeforeGeoIP(t *testing.T) {
	s, backend := orderServer(t)
	// Une base GeoIP absente refuse en 403 (db_unavailable) ; le plugin absent refuse en 503. Le plugin juge d'abord.
	route := &router.Route{ID: "ord-plug-geo", Host: "ord-plug-geo.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		GeoIP:   &router.GeoIPConfig{Mode: "deny", Countries: []string{"XX"}, DBPath: "/nulle/part/absent.mmdb"},
		Plugins: []router.PluginRef{{Name: "absent"}}}

	if code := send(s, route, "/", "198.51.100.9", ""); code != http.StatusServiceUnavailable {
		t.Fatalf("%d : le plugin doit juger avant GeoIP", code)
	}
	if n := blocked(route.Host, "geoip"); n != 0 {
		t.Fatalf("GeoIP a refusé %v fois alors que le plugin juge avant", n)
	}
}

func stageNames(stages []dispatchStage) []string {
	out := make([]string, len(stages))
	for i, st := range stages {
		out[i] = st.name
	}
	return out
}

// L'ordre complet d'une route qui active tout : celui de l'assemblage câblé à la main d'avant le registre.
func TestDispatchStages_FullOrderIsTheHistoricalOne(t *testing.T) {
	s, _ := orderServer(t)
	no := false
	route := &router.Route{ID: "ord-full", Host: "ord-full.test", Type: router.RouteHTTP, RequestID: &no,
		WAF:      &router.WAFConfig{Enabled: true},
		Bot:      &router.BotConfig{Enabled: true},
		IPFilter: &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"192.0.2.0/24"}},
		GeoIP:    &router.GeoIPConfig{Mode: "deny", Countries: []string{"XX"}},
		Plugins:  []router.PluginRef{{Name: "p"}}}

	got := stageNames(s.dispatchStages(route, "ord-full"))
	want := []string{"maintenance", "signed_url", "bandwidth", "compress", "transform", "request_id", "waf", "bot", "request_vars",
		"backpressure", "limit_conn", "rate_limit", "ip_filter", "plugins", "geo_ip", "security_headers", "cors", "mtls", "jwt", "sso",
		"openapi", "request_schema", "graphql"}
	if len(got) != len(want) {
		t.Fatalf("étapes : %v\nattendu : %v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("étapes : %v\nattendu : %v", got, want)
		}
	}
}

// Une route sans détecteur ni option n'enveloppe aucun détecteur : rien ne coûte là où rien n'est configuré.
func TestDispatchStages_InactiveDetectorsAreAbsent(t *testing.T) {
	s, _ := orderServer(t)
	route := &router.Route{ID: "ord-min", Host: "ord-min.test", Type: router.RouteHTTP,
		WAF: &router.WAFConfig{Enabled: false}, Bot: &router.BotConfig{Enabled: false}, IPFilter: &router.IPFilterConfig{Mode: "deny"}}
	for _, name := range stageNames(s.dispatchStages(route, "ord-min")) {
		switch name {
		case "waf", "bot", "ip_filter", "geo_ip", "plugins", "request_id":
			t.Errorf("%s ne doit pas figurer dans la chaîne d'une route qui ne l'active pas", name)
		}
	}
}

// Les rangs sont uniques : deux étapes au même rang auraient un ordre qui dépend du tri.
func TestDispatchStages_RanksAreUnique(t *testing.T) {
	s, _ := orderServer(t)
	no := false
	route := &router.Route{ID: "ord-rank", Host: "ord-rank.test", Type: router.RouteHTTP, RequestID: &no,
		WAF: &router.WAFConfig{Enabled: true}, Bot: &router.BotConfig{Enabled: true},
		IPFilter: &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"192.0.2.0/24"}}, GeoIP: &router.GeoIPConfig{Mode: "deny"},
		Plugins: []router.PluginRef{{Name: "p"}}}
	seen := map[int]string{}
	for _, st := range s.dispatchStages(route, "ord-rank") {
		if other, dup := seen[st.rank]; dup {
			t.Errorf("rang %d partagé par %s et %s", st.rank, other, st.name)
		}
		seen[st.rank] = st.name
	}
}

func TestDetectorDecisions_AreCounted(t *testing.T) {
	s, backend := orderServer(t)
	route := &router.Route{ID: "ord-dec", Host: "ord-dec.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		IPFilter: &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"203.0.113.0/24"}}}
	pass := metrics.Detector.Decisions.WithLabelValues("ip_filter", "pass")
	block := metrics.Detector.Decisions.WithLabelValues("ip_filter", "block")
	p0, b0 := testutil.ToFloat64(pass), testutil.ToFloat64(block)

	send(s, route, "/", "203.0.113.20", "") // interdite
	send(s, route, "/", "198.51.100.20", "")
	send(s, route, "/", "198.51.100.21", "")
	if got := testutil.ToFloat64(block) - b0; got != 1 {
		t.Errorf("blocages : %v, attendu 1", got)
	}
	if got := testutil.ToFloat64(pass) - p0; got != 2 {
		t.Errorf("laissés passer : %v, attendu 2", got)
	}
}
