// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxypipeline

import (
	"encoding/json"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/modules"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestValidateBackendURLHTTP(t *testing.T) {
	if err := validateBackendURL(router.RouteHTTP, "http://10.0.0.1:8080"); err != nil {
		t.Fatal(err)
	}
	if err := validateBackendURL(router.RouteHTTP, "not-a-url"); err == nil {
		t.Fatal("expected error")
	}
}

func TestValidateBackendURLL4(t *testing.T) {
	if err := validateBackendURL(router.RouteTCP, "10.0.0.5:5432"); err != nil {
		t.Fatal(err)
	}
	if err := validateBackendURL(router.RouteTCP, "10.0.0.5"); err == nil {
		t.Fatal("expected error")
	}
}

func TestRunDryRunTCPListenPortConflict(t *testing.T) {
	peerCfg, _ := json.Marshal(map[string]any{
		"id": "a", "type": "tcp", "listen_port": 5432,
		"backends": []map[string]any{{"url": "10.0.0.1:5432", "weight": 1}},
		"lb":       "round_robin",
	})
	candCfg, _ := json.Marshal(map[string]any{
		"id": "b", "type": "tcp", "listen_port": 5432,
		"backends": []map[string]any{{"url": "10.0.0.2:5432", "weight": 1}},
		"lb":       "round_robin",
	})
	peer := &proxystore.Envelope{ID: "a", Status: proxystore.StatusProduction, Config: peerCfg}
	cand := &proxystore.Envelope{ID: "b", Revision: "r1", Status: proxystore.StatusPending, Config: candCfg}
	res := RunDryRun(cand, []*proxystore.Envelope{peer}, DryRunOptions{})
	if res.OK {
		t.Fatalf("expected conflict, errors=%v", res.Errors)
	}
}

func TestRunDryRunAcceptsHTTPSType(t *testing.T) {
	cfg, _ := json.Marshal(map[string]any{
		"id": "p1", "host": "auth.example.fr", "type": "https",
		"tls_enabled": true,
		"backends":    []map[string]any{{"url": "http://127.0.0.1:1411", "weight": 1}},
		"lb":          "round_robin",
	})
	cand := &proxystore.Envelope{ID: "p1", Revision: "r1", Host: "auth.example.fr", Status: proxystore.StatusPending, Config: cfg}
	res := RunDryRun(cand, nil, DryRunOptions{})
	if !res.OK {
		t.Fatalf("https alias should pass, errors=%v", res.Errors)
	}
}

func TestRunDryRunTCPAndUDPSamePortOK(t *testing.T) {
	tcpCfg, _ := json.Marshal(map[string]any{
		"id": "tcp", "host": "Minecraft", "type": "tcp", "listen_port": 25565,
		"backends": []map[string]any{{"url": "203.0.113.10:25565", "weight": 1}},
		"lb":       "round_robin",
	})
	udpCfg, _ := json.Marshal(map[string]any{
		"id": "udp", "host": "Minecraft", "type": "udp", "listen_port": 25565,
		"backends": []map[string]any{{"url": "203.0.113.10:25566", "weight": 1}},
		"lb":       "round_robin",
	})
	peer := &proxystore.Envelope{ID: "tcp", Status: proxystore.StatusProduction, Config: tcpCfg}
	cand := &proxystore.Envelope{ID: "udp", Revision: "r1", Status: proxystore.StatusPending, Config: udpCfg}
	res := RunDryRun(cand, []*proxystore.Envelope{peer}, DryRunOptions{})
	if !res.OK {
		t.Fatalf("tcp+udp same port should pass, errors=%v", res.Errors)
	}
}

func TestRewriteHTTPSTypeInConfig(t *testing.T) {
	in := []byte(`{"host":"auth.example.fr","type":"https","tls_enabled":true,"extra":1}`)
	out := rewriteHTTPSTypeInConfig(in)
	var m map[string]any
	if err := json.Unmarshal(out, &m); err != nil {
		t.Fatal(err)
	}
	if m["type"] != "http" {
		t.Fatalf("type=%v", m["type"])
	}
	if m["tls_enabled"] != true {
		t.Fatalf("tls_enabled=%v", m["tls_enabled"])
	}
	if m["extra"] != float64(1) {
		t.Fatalf("extra field lost: %v", m["extra"])
	}
}

func TestValidateRouteBasicsBotChallengeAndProxyProtocol(t *testing.T) {
	base := func() *router.Route {
		return &router.Route{Type: router.RouteHTTP, Host: "a.test", Backends: []router.Backend{{URL: "http://127.0.0.1:1"}}}
	}
	if errs := validateRouteBasics(base()); len(errs) != 0 {
		t.Fatalf("route valide refusée : %v", errs)
	}
	cases := map[string]func(*router.Route){
		"proxy_protocol":  func(r *router.Route) { r.ProxyProtocol = "v3" },
		"provider":        func(r *router.Route) { r.Bot = &router.BotConfig{ChallengeProvider: "recaptcha"} },
		"clés manquantes": func(r *router.Route) { r.Bot = &router.BotConfig{ChallengeProvider: "turnstile"} },
		"difficulté":      func(r *router.Route) { r.Bot = &router.BotConfig{ChallengeDifficulty: 30} },
		"ttl":             func(r *router.Route) { r.Bot = &router.BotConfig{ChallengeTTL: "dix minutes"} },
	}
	for name, mutate := range cases {
		r := base()
		mutate(r)
		if errs := validateRouteBasics(r); len(errs) == 0 {
			t.Errorf("%s : aucune erreur", name)
		}
	}
	ok := base()
	ok.ProxyProtocol = "v2"
	ok.Bot = &router.BotConfig{ChallengeProvider: "hcaptcha", ChallengeSiteKey: "k", ChallengeProviderSecret: "s", ChallengeDifficulty: 20, ChallengeTTL: "12h"}
	if errs := validateRouteBasics(ok); len(errs) != 0 {
		t.Errorf("config valide refusée : %v", errs)
	}
}

func TestValidateRouteBasicsRejectsInvalidOpenAPIAndGRPCTranscode(t *testing.T) {
	base := func() *router.Route {
		return &router.Route{ID: "r", Type: router.RouteHTTP, Host: "api.example.fr", Backends: []router.Backend{{URL: "http://10.0.0.1:8080", Weight: 1}}}
	}
	ok := base()
	ok.OpenAPI = &router.OpenAPIConfig{Enabled: true, Spec: json.RawMessage(`"openapi: 3.0.0\npaths:\n  /a:\n    get: {}"`)}
	ok.GRPCTranscode = &router.GRPCTranscodeConfig{Enabled: true, AutoMapping: true, Proto: map[string]string{"a.proto": `syntax = "proto3"; package p; message M {} service S { rpc F(M) returns (M); }`}}
	if errs := validateRouteBasics(ok); len(errs) != 0 {
		t.Fatalf("configuration valide refusée : %v", errs)
	}

	bad := base()
	bad.OpenAPI = &router.OpenAPIConfig{Enabled: true, Spec: json.RawMessage(`"swagger: '2.0'"`)}
	bad.GRPCTranscode = &router.GRPCTranscodeConfig{Enabled: true}
	if errs := validateRouteBasics(bad); len(errs) < 2 {
		t.Fatalf("openapi et grpc_transcode invalides doivent être signalés : %v", errs)
	}
}

func TestValidateRouteBasicsRejectsInvalidDetectors(t *testing.T) {
	base := func() *router.Route {
		return &router.Route{Type: router.RouteHTTP, Host: "a.test", Backends: []router.Backend{{URL: "http://127.0.0.1:1"}}}
	}
	bad := map[string]func(*router.Route){
		"ip_filter mode": func(r *router.Route) {
			r.IPFilter = &router.IPFilterConfig{Mode: "block", CIDRs: []string{"10.0.0.0/8"}}
		},
		"ip_filter vide mode": func(r *router.Route) { r.IPFilter = &router.IPFilterConfig{CIDRs: []string{"10.0.0.0/8"}} },
		"ip_filter CIDR": func(r *router.Route) {
			r.IPFilter = &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"10.0.0.0/40"}}
		},
		"geo_ip mode":      func(r *router.Route) { r.GeoIP = &router.GeoIPConfig{Mode: "ban", Countries: []string{"CN"}} },
		"geo_ip pays":      func(r *router.Route) { r.GeoIP = &router.GeoIPConfig{Mode: "deny", Countries: []string{"CHINE"}} },
		"geo_ip sans mode": func(r *router.Route) { r.GeoIP = &router.GeoIPConfig{Countries: []string{"CN"}} },
		"waf mode":         func(r *router.Route) { r.WAF = &router.WAFConfig{Enabled: true, Mode: "off"} },
		"waf regex": func(r *router.Route) {
			r.WAF = &router.WAFConfig{Enabled: true, CustomRules: []router.CustomRule{{ID: 1, Pattern: "("}}}
		},
		"waf proxys": func(r *router.Route) { r.WAF = &router.WAFConfig{Enabled: true, TrustedProxies: []string{"nope"}} },
		"bot mode":   func(r *router.Route) { r.Bot = &router.BotConfig{Enabled: true, Mode: "strict"} },
	}
	for name, mutate := range bad {
		r := base()
		mutate(r)
		if errs := validateRouteBasics(r); len(errs) == 0 {
			t.Errorf("%s : aucune erreur", name)
		}
	}
	// Détecteurs inactifs ou valides : acceptés.
	for name, mutate := range map[string]func(*router.Route){
		"ip_filter sans adresse": func(r *router.Route) { r.IPFilter = &router.IPFilterConfig{Mode: "allow"} },
		"geo_ip vide":            func(r *router.Route) { r.GeoIP = &router.GeoIPConfig{} },
		"ip_filter valide": func(r *router.Route) {
			r.IPFilter = &router.IPFilterConfig{Mode: "Allow", CIDRs: []string{"10.0.0.0/8", "203.0.113.1"}}
		},
		"geo_ip valide": func(r *router.Route) { r.GeoIP = &router.GeoIPConfig{Mode: "deny", Countries: []string{"cn", "RU"}} },
		"waf valide": func(r *router.Route) {
			r.WAF = &router.WAFConfig{Enabled: true, Mode: "detect", ExcludeIDs: []int{920350}, MaxBodyMB: 2}
		},
		"bot valide": func(r *router.Route) { r.Bot = &router.BotConfig{Enabled: true, Mode: "challenge", JSChallenge: true} },
	} {
		r := base()
		mutate(r)
		if errs := validateRouteBasics(r); len(errs) != 0 {
			t.Errorf("%s refusée : %v", name, errs)
		}
	}
}

func TestValidatePlugins(t *testing.T) {
	known := map[string]plugins.Manifest{
		"geo": {Name: "geo", Fields: []modules.Field{{Key: "header", Label: "En-tête", Kind: modules.KindText, Required: true}}},
		"raw": {Name: "raw"},
	}
	route := func(refs ...router.PluginRef) *router.Route { return &router.Route{Plugins: refs} }
	opts := DryRunOptions{KnownPlugins: known}
	if errs := validatePlugins(route(router.PluginRef{Name: "geo", Config: map[string]any{"header": "X-Geo"}}, router.PluginRef{Name: "raw"}), opts); len(errs) != 0 {
		t.Errorf("config valide refusée : %v", errs)
	}
	for name, r := range map[string]*router.Route{
		"inconnu":      route(router.PluginRef{Name: "autre"}),
		"champ requis": route(router.PluginRef{Name: "geo"}),
		"clé inconnue": route(router.PluginRef{Name: "geo", Config: map[string]any{"header": "X", "extra": 1}}),
		"doublon":      route(router.PluginRef{Name: "raw"}, router.PluginRef{Name: "raw"}),
		"nom vide":     route(router.PluginRef{}),
	} {
		if errs := validatePlugins(r, opts); len(errs) == 0 {
			t.Errorf("%s : accepté", name)
		}
	}
	// Sans liste de plugins connue (passerelle sans gestionnaire), seule la forme est contrôlée.
	if errs := validatePlugins(route(router.PluginRef{Name: "quelconque"}), DryRunOptions{}); len(errs) != 0 {
		t.Errorf("forme seule : %v", errs)
	}
}
