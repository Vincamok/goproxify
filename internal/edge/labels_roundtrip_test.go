// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
	"github.com/vincamok/goproxify/internal/edge/geoip"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/labels"
)

// routeFromLabels rejoue le chemin réel d'un conteneur : labels → ProxySpec (Agent) → payload → route (passerelle).
func routeFromLabels(t *testing.T, g *labels.Generated) (*router.Route, *labels.Generated) {
	t.Helper()
	m := map[string]string{}
	for _, p := range g.Labels {
		v := p.Value
		for _, name := range labels.EnvTokens(v) {
			v = strings.ReplaceAll(v, "{{env:"+name+"}}", "valeur-secrete")
		}
		m[p.Key] = v
	}
	spec := docker.ParseLabels("c1", "c1", "img", "", m, nil, "10.0.0.2")
	if spec == nil {
		t.Fatalf("labels refusés par l'Agent : %v", m)
	}
	payload := map[string]any{
		"host": spec.Host, "aliases": spec.Aliases, "paths": spec.Paths, "route_type": spec.Type,
		"backends": []string{spec.BackendURL}, "tls_enabled": spec.TLS, "passthrough": spec.Passthrough,
		"source": "docker", "container_id": "c1", "role": spec.Role,
	}
	docker.AttachSecurityPayload(payload, spec)
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	var p agentContainerPayload
	if err := json.Unmarshal(raw, &p); err != nil {
		t.Fatal(err)
	}
	if len(p.LabelErrors) > 0 {
		t.Fatalf("labels illisibles pour l'Agent : %v", p.LabelErrors)
	}
	if errs := discoverySecurityErrors(&p, "", nil); len(errs) > 0 {
		t.Fatalf("la passerelle refuse les labels : %v", errs)
	}
	rt := &router.Route{Host: p.Host, Aliases: p.Aliases, TLSEnabled: p.TLSEnabled, TLSPassthrough: p.Passthrough}
	for _, u := range p.Backends {
		rt.Backends = append(rt.Backends, router.Backend{URL: u})
	}
	applyDiscoveryHostExtras(rt, &p)
	applyDiscoverySecurity(rt, &p, "")
	return rt, g
}

func richRoute() *router.Route {
	t := true
	return &router.Route{
		ID: "r1", Host: "app.example.fr", Aliases: []string{"www.example.fr"}, Type: router.RouteHTTP,
		Backends: []router.Backend{{URL: "https://app:8443", Weight: 1}}, TLSEnabled: true,
		PreserveHost: &t, Websocket: &t, RequestID: &t, HttpVersion: "2",
		StripPrefix: "/api", PathRewrite: "/api→/v2/api",
		ConnectTimeout: 5 * time.Second, ResponseTimeout: 30 * time.Second, SendTimeout: 10 * time.Second,
		MaxBodySize: 10 << 20,
		LB:          router.LBWeighted, StickyCookie: "GPXSESSION", SlowStartSec: 30,
		Retry:          &router.RetryConfig{Attempts: 3, InitialWait: 500 * time.Millisecond},
		CircuitBreaker: &router.CBConfig{Threshold: 5, Timeout: 30 * time.Second},
		LimitConn:      &router.LimitConnConfig{MaxPerIP: 50},
		Backpressure:   &router.BackpressureConfig{MaxInflight: 200, Queue: 100, QueueTimeoutMs: 2000},
		HeadersManipulation: &router.HeadersManipulationConfig{
			RequestSetHeader: map[string]string{"X-Foo": "bar", "Authorization": "Bearer abc"},
		},
		Transform:      &router.RequestTransform{RemoveResponseHeaders: []string{"X-Powered-By", "Server"}},
		RateLimit:      &router.RateLimitConfig{RequestsPerSecond: 100, Burst: 50},
		IPFilter:       &router.IPFilterConfig{Mode: "allow", CIDRs: []string{"10.0.0.0/8", "192.168.0.0/16"}},
		GeoIP:          &router.GeoIPConfig{DBPath: geoip.DefaultDBPath, Mode: "deny", Countries: []string{"CN", "RU"}},
		CORS:           labels.ParseCORS("https://a.example.fr,https://b.example.fr"),
		WAF:            &router.WAFConfig{Enabled: true, Mode: "detect", ExcludeIDs: []int{942100, 941100}, MaxBodyMB: 10, AnomalyThreshold: 10, BehaviorEnabled: true, BehaviorWindowSec: 60, BehaviorThreshold: 8, TrustedProxies: []string{"10.0.0.0/8"}},
		Bot:            &router.BotConfig{Enabled: true, Mode: "challenge", JSChallenge: true},
		SnippetIDs:     []string{"waf-default", "headers-secure"},
		AuthProviderID: "authentik-prod",
		EphorWhitelist: []string{"192.168.1.5", "10.0.0.0/8"},
		JWT:            &router.JWTConfig{Enabled: true, JWKSURL: "https://idp.example.com/.well-known/jwks.json", Issuer: "https://idp.example.com", Audience: "my-api"},
		MTLS:           &router.MTLSConfig{Enabled: true, CACertFile: "/etc/goproxify/ca.pem", RequireClientCert: true},
		Cache:          &router.CacheConfig{Enabled: true, ValidRules: []router.CacheValidRule{{TTL: "60s"}}},
		Logging:        &router.RouteLoggingConfig{AccessLog: true, Format: "json", Level: "warn"},
		Plugins: []router.PluginRef{
			{Name: "geo-headers", Config: map[string]any{"header": "X-Geo", "strict": true, "ttl": float64(5)}},
			{Name: "audit"},
		},
	}
}

func TestGeneratedLabelsRebuildTheRoute(t *testing.T) {
	orig := richRoute()
	g := labels.FromRoute(orig)
	if len(g.Unsupported) > 0 {
		t.Fatalf("une route entièrement exprimable en labels ne doit rien signaler : %v", g.Unsupported)
	}
	got, _ := routeFromLabels(t, g)

	if got.Host != orig.Host || !reflect.DeepEqual(got.Aliases, orig.Aliases) {
		t.Fatalf("hôtes : %q %v", got.Host, got.Aliases)
	}
	if len(got.Backends) != 1 || got.Backends[0].URL != orig.Backends[0].URL {
		t.Fatalf("backend : %+v", got.Backends)
	}
	if !got.TLSEnabled {
		t.Fatal("tls perdu")
	}
	checks := []struct {
		name      string
		want, got any
	}{
		{"preserve_host", orig.PreserveHost, got.PreserveHost},
		{"websocket", orig.Websocket, got.Websocket},
		{"request_id", orig.RequestID, got.RequestID},
		{"http_version", orig.HttpVersion, got.HttpVersion},
		{"strip_prefix", orig.StripPrefix, got.StripPrefix},
		{"path_rewrite", orig.PathRewrite, got.PathRewrite},
		{"connect_timeout", orig.ConnectTimeout, got.ConnectTimeout},
		{"response_timeout", orig.ResponseTimeout, got.ResponseTimeout},
		{"send_timeout", orig.SendTimeout, got.SendTimeout},
		{"max_body_size", orig.MaxBodySize, got.MaxBodySize},
		{"lb", orig.LB, got.LB},
		{"sticky_cookie", orig.StickyCookie, got.StickyCookie},
		{"slow_start", orig.SlowStartSec, got.SlowStartSec},
		{"retry", orig.Retry, got.Retry},
		{"circuit_breaker", orig.CircuitBreaker, got.CircuitBreaker},
		{"limit_conn", orig.LimitConn, got.LimitConn},
		{"backpressure", orig.Backpressure, got.Backpressure},
		{"remove_response_headers", orig.Transform.RemoveResponseHeaders, got.Transform.RemoveResponseHeaders},
		{"rate_limit", orig.RateLimit, got.RateLimit},
		{"ip_filter", orig.IPFilter, got.IPFilter},
		{"geo_ip", orig.GeoIP, got.GeoIP},
		{"cors", orig.CORS, got.CORS},
		{"waf", orig.WAF, got.WAF},
		{"bot", orig.Bot, got.Bot},
		{"snippets", orig.SnippetIDs, got.SnippetIDs},
		{"auth_provider", orig.AuthProviderID, got.AuthProviderID},
		{"ephor_whitelist", orig.EphorWhitelist, got.EphorWhitelist},
		{"jwt", orig.JWT, got.JWT},
		{"mtls", orig.MTLS, got.MTLS},
		{"cache", orig.Cache, got.Cache},
		{"logging", orig.Logging, got.Logging},
		{"plugins", orig.Plugins, got.Plugins},
	}
	for _, c := range checks {
		if !reflect.DeepEqual(c.want, c.got) {
			wj, _ := json.Marshal(c.want)
			gj, _ := json.Marshal(c.got)
			t.Errorf("%s : attendu %s, relu %s", c.name, wj, gj)
		}
	}
	hdr := got.HeadersManipulation.RequestSetHeader
	if hdr["X-Foo"] != "bar" {
		t.Errorf("en-tête ajouté perdu : %v", hdr)
	}
}

func TestSecretsNeverLeakIntoLabels(t *testing.T) {
	orig := richRoute()
	orig.Plugins[0].Config["api_token"] = "tok-123"
	g := labels.FromRoute(orig)
	for _, f := range labels.Formats {
		for _, withEnv := range []bool{true, false} {
			out, err := g.Render(f, withEnv)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(out.Text+out.Env, "Bearer abc") || strings.Contains(out.Text+out.Env, "tok-123") {
				t.Fatalf("%s (env=%v) : un secret est écrit en clair\n%s", f, withEnv, out.Text)
			}
		}
	}
	if env := g.Env(); len(env) != 2 {
		t.Fatalf("deux variables attendues (en-tête, plugin), obtenu %v", env)
	}
}

func TestUnsupportedSettingsAreReported(t *testing.T) {
	orig := richRoute()
	orig.Locations = []router.Location{{Path: "/x", PathType: "prefix"}}
	orig.Compression = &router.CompressionConfig{Enabled: true}
	orig.RateLimit.Quota = 100
	g := labels.FromRoute(orig)
	joined := strings.Join(g.Unsupported, " | ")
	for _, want := range []string{"locations", "rate_limit"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q devrait être signalé : %s", want, joined)
		}
	}
}
