// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"strings"
	"testing"
)

func TestBuildProxyLabels(t *testing.T) {
	out, err := BuildProxyLabels([]byte(`{"host":"app.example.fr","type":"https","backends":[{"url":"http://app:80"}],
		"headers_manipulation":{"request_set_header":{"X-Api-Key":"super-secret"}},"compression":{"enabled":true}}`))
	if err != nil {
		t.Fatal(err)
	}
	var tls bool
	for _, l := range out.Labels {
		if l.Key == "goproxify.tls" && l.Value == "true" {
			tls = true
		}
		if strings.Contains(l.Value, "super-secret") {
			t.Fatalf("secret en clair dans %s", l.Key)
		}
	}
	if !tls {
		t.Error("le type https de l'UI doit donner goproxify.tls")
	}
	if len(out.Env) != 1 || !strings.HasPrefix(out.Env[0], "GPX_HDR_") {
		t.Errorf("variables : %v", out.Env)
	}
	if len(out.Unsupported) != 1 || out.Unsupported[0] != "compression" {
		t.Errorf("la compression n'a pas de label : %v", out.Unsupported)
	}
	for _, f := range []string{"compose", "portainer", "portainer_inline", "docker_run", "kubernetes"} {
		o, ok := out.Formats[f]
		if !ok || o.Text == "" {
			t.Errorf("format %s manquant", f)
		}
		if strings.Contains(o.Text+o.Env, "super-secret") {
			t.Errorf("format %s : secret en clair", f)
		}
	}
}
