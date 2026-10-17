// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func sampleRoute() *router.Route {
	return &router.Route{
		ID: "r", Host: "app.example.fr", Type: router.RouteHTTP, TLSEnabled: true,
		Backends: []router.Backend{{URL: "http://app:3000"}},
		HeadersManipulation: &router.HeadersManipulationConfig{
			RequestSetHeader: map[string]string{"X-Env": "prod$1", "Authorization": "Bearer s3cret"},
		},
		RateLimit: &router.RateLimitConfig{RequestsPerSecond: 2.5, Burst: 5},
	}
}

func TestFromRouteBasics(t *testing.T) {
	g := FromRoute(sampleRoute())
	want := map[string]string{
		"goproxify.enable":      "true",
		"goproxify.host":        "app.example.fr",
		"goproxify.backend":     "http://app:3000",
		"goproxify.tls":         "true",
		"goproxify.rate_limit":  "2.5/s:5",
		"goproxify.headers.add": "Authorization:{{env:GPX_HDR_AUTHORIZATION}},X-Env:prod$1",
	}
	got := map[string]string{}
	for _, p := range g.Labels {
		got[p.Key] = p.Value
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("%s = %q, attendu %q", k, got[k], v)
		}
	}
	if env := g.Env(); len(env) != 1 || env[0] != "GPX_HDR_AUTHORIZATION" {
		t.Fatalf("variables : %v", env)
	}
	if len(g.Unsupported) != 0 {
		t.Fatalf("rien à signaler : %v", g.Unsupported)
	}
}

func TestRenderFormats(t *testing.T) {
	g := FromRoute(sampleRoute())

	compose, _ := g.Render(FormatCompose, true)
	if !strings.Contains(compose.Text, `goproxify.headers.add: "Authorization:${GPX_HDR_AUTHORIZATION},X-Env:prod$$1"`) {
		t.Errorf("compose : $ littéral doublé, variable conservée\n%s", compose.Text)
	}
	if compose.Env != "GPX_HDR_AUTHORIZATION=\n" {
		t.Errorf("compose .env : %q", compose.Env)
	}

	inline, _ := g.Render(FormatPortainer, false)
	if !strings.Contains(inline.Text, "Authorization:CHANGE_ME") || inline.Env != "" {
		t.Errorf("portainer sans stack.env : secret à remplacer, pas de fichier\n%s", inline.Text)
	}
	stack, _ := g.Render(FormatPortainer, true)
	if !strings.Contains(stack.Text, "${GPX_HDR_AUTHORIZATION}") || stack.Env == "" {
		t.Errorf("portainer avec stack.env\n%s", stack.Text)
	}

	run, _ := g.Render(FormatDockerRun, true)
	if !strings.Contains(run.Text, `-l 'goproxify.host=app.example.fr'`) ||
		!strings.Contains(run.Text, `-l "goproxify.headers.add=Authorization:${GPX_HDR_AUTHORIZATION},X-Env:prod\$1"`) {
		t.Errorf("docker run : guillemets simples pour le littéral, doubles pour les variables\n%s", run.Text)
	}
	if run.Env != "export GPX_HDR_AUTHORIZATION=\n" {
		t.Errorf("docker run env : %q", run.Env)
	}

	k8s, _ := g.Render(FormatKubernetes, true)
	for _, want := range []string{"kind: Service", `goproxify.enabled: "true"`, "targetPort: 3000", "Authorization:CHANGE_ME"} {
		if !strings.Contains(k8s.Text, want) {
			t.Errorf("kubernetes : %q absent\n%s", want, k8s.Text)
		}
	}
	if strings.Contains(k8s.Text, "goproxify.enable:") {
		t.Errorf("kubernetes : l'annotation enable est portée par le label enabled")
	}
}

func TestUnsupportedSettings(t *testing.T) {
	r := sampleRoute()
	r.Backends = append(r.Backends, router.Backend{URL: "http://b:3000"})
	r.Locations = []router.Location{{Path: "/x"}}
	r.RateLimit.Quota = 10
	f := false
	r.Websocket = &f
	g := FromRoute(r)
	joined := strings.Join(g.Unsupported, " | ")
	for _, want := range []string{"backends multiples", "locations", "rate_limit", "websocket désactivé"} {
		if !strings.Contains(joined, want) {
			t.Errorf("%q absent de : %s", want, joined)
		}
	}
}

func TestServiceName(t *testing.T) {
	for in, want := range map[string]string{"app.example.fr": "app", "My_App.x.fr": "my-app", "": "app", "*.x.fr": "app"} {
		if got := ServiceName(in); got != want {
			t.Errorf("ServiceName(%q) = %q, attendu %q", in, got, want)
		}
	}
}
