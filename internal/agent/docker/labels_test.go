// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package docker

import (
	"strings"
	"testing"
)

func TestParseLabelsMultiCanaryRole(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable:       "true",
		LabelHost:         "app.example.fr",
		LabelCanary:       "true",
		LabelCanaryWeight: "25",
	}, nil, "10.0.0.5")
	if len(specs) != 1 {
		t.Fatalf("len = %d", len(specs))
	}
	if specs[0].Role != RoleCanary {
		t.Fatalf("Role = %q, want canary", specs[0].Role)
	}
	if specs[0].CanaryWeight != 25 {
		t.Fatalf("CanaryWeight = %d, want 25", specs[0].CanaryWeight)
	}
}

func TestParseLabelsMultiCanaryDefaultWeight(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
		LabelCanary: "true",
	}, nil, "10.0.0.5")
	if specs[0].CanaryWeight != 10 {
		t.Fatalf("CanaryWeight = %d, want 10", specs[0].CanaryWeight)
	}
}

func TestParseLabelsMultiShadowRole(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
		LabelShadow: "true",
	}, nil, "10.0.0.5")
	if specs[0].Role != RoleShadow {
		t.Fatalf("Role = %q, want shadow", specs[0].Role)
	}
}

func TestParseLabelsMultiCanaryWinsOverShadow(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
		LabelCanary: "true",
		LabelShadow: "true",
	}, nil, "10.0.0.5")
	if specs[0].Role != RoleCanary {
		t.Fatalf("Role = %q, want canary (priority)", specs[0].Role)
	}
}

func TestParseLabelsMultiNormalRole(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "app.example.fr",
	}, nil, "10.0.0.5")
	if specs[0].Role != RoleNormal {
		t.Fatalf("Role = %q, want normal", specs[0].Role)
	}
}

func TestParseLabelsMultiSecurityFields(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable:       "true",
		LabelHost:         "app.example.fr",
		LabelRateLimitRPS: "80",
		LabelRateLimitBurst: "40",
		LabelIPFilter:     "allow:10.0.0.0/8",
		LabelSnippets:     "waf-default, headers-secure",
		LabelAuthProvider: "oidc-1",
		LabelWAF:          "detect",
		LabelBot:          "true",
	}, nil, "10.0.0.5")
	if len(specs) != 1 {
		t.Fatalf("len = %d", len(specs))
	}
	s := specs[0]
	if s.RateLimit != "80/s:40" {
		t.Fatalf("RateLimit = %q", s.RateLimit)
	}
	if s.IPFilter != "allow:10.0.0.0/8" {
		t.Fatalf("IPFilter = %q", s.IPFilter)
	}
	if s.SnippetIDs != "waf-default, headers-secure" || s.AuthProviderID != "oidc-1" {
		t.Fatalf("snippets/auth = %q / %q", s.SnippetIDs, s.AuthProviderID)
	}
	if s.WAF != "detect" || s.Bot != "true" {
		t.Fatalf("waf/bot = %q / %q", s.WAF, s.Bot)
	}
}

func TestParseLabelsMultiCanaryWeightClamp(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable:       "true",
		LabelHost:         "app.example.fr",
		LabelCanary:       "true",
		LabelCanaryWeight: "150",
	}, nil, "10.0.0.5")
	if specs[0].CanaryWeight != 100 {
		t.Fatalf("CanaryWeight = %d, want 100", specs[0].CanaryWeight)
	}
}

func TestParseLabelsMultiHostAliasesAndPaths(t *testing.T) {
	specs := ParseLabelsMulti("cid1", "/app", "img", "net", map[string]string{
		LabelEnable: "true",
		LabelHost:   "https://a.example.fr/admin, b.example.fr, a.example.fr/app",
	}, nil, "10.0.0.5")
	if len(specs) != 1 {
		t.Fatalf("len = %d, want 1 spec with aliases", len(specs))
	}
	s := specs[0]
	if s.Host != "a.example.fr" {
		t.Fatalf("Host = %q", s.Host)
	}
	if len(s.Aliases) != 1 || s.Aliases[0] != "b.example.fr" {
		t.Fatalf("Aliases = %#v", s.Aliases)
	}
	if len(s.Paths) != 2 || s.Paths[0] != "/admin" || s.Paths[1] != "/app" {
		t.Fatalf("Paths = %#v", s.Paths)
	}
}

func TestParsePluginConfigLabels(t *testing.T) {
	got := parsePluginConfigLabels(map[string]string{
		"goproxify.plugins":            "geo,audit",
		"goproxify.plugin.geo.header":  "X-Geo",
		"goproxify.plugin.geo.strict":  "true",
		"goproxify.plugin.geo.limit":   "5",
		"goproxify.plugin.audit.mode":  "log",
		"goproxify.plugin..vide":       "x",
		"goproxify.plugin.sanscle":     "x",
		"goproxify.pluginx.geo.header": "ignoré",
	})
	if len(got) != 2 || got["geo"]["header"] != "X-Geo" || got["geo"]["strict"] != true || got["geo"]["limit"] != float64(5) || got["audit"]["mode"] != "log" {
		t.Fatalf("config = %+v", got)
	}
	if parsePluginConfigLabels(map[string]string{"goproxify.host": "a"}) != nil {
		t.Error("sans label de plugin, aucune configuration")
	}
}

// Un label de sécurité illisible est signalé à la passerelle au lieu d'être ignoré en silence.
func TestAttachSecurityPayload_ReportsUnreadableLabels(t *testing.T) {
	spec := &ProxySpec{Host: "a.test", IPFilter: "deny:", GeoIP: "deny:", WAF: "peut-etre", Bot: "challenge", RateLimit: "vite", JWT: "pas-une-url", MTLS: "ca.pem-introuvable"}
	payload := map[string]any{}
	AttachSecurityPayload(payload, spec)
	errs, _ := payload["label_errors"].([]string)
	joined := strings.Join(errs, " | ")
	for _, label := range []string{"ip_filter", "geo_ip", "waf", "bot", "rate_limit", "jwt"} {
		if !strings.Contains(joined, "goproxify."+label+"=") {
			t.Errorf("label %s non signalé : %v", label, errs)
		}
	}
	// Désactivations explicites et valeurs valides : aucune erreur.
	ok := map[string]any{}
	AttachSecurityPayload(ok, &ProxySpec{Host: "a.test", WAF: "false", Bot: "off", IPFilter: "deny:10.0.0.0/8", Plugins: "geo", PluginConfig: map[string]map[string]any{"geo": {"header": "X"}}})
	if _, bad := ok["label_errors"]; bad {
		t.Errorf("erreurs inattendues : %v", ok["label_errors"])
	}
	refs, _ := ok["plugins"].([]map[string]any)
	if len(refs) != 1 || refs[0]["name"] != "geo" || refs[0]["config"].(map[string]any)["header"] != "X" {
		t.Errorf("plugins = %+v", ok["plugins"])
	}
}
