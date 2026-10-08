// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"os"
	"reflect"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
)

// Caractérisation de la construction des sources de découverte. Ce fichier a précédé la migration
// vers le registre de modules : quelles sources New() active selon la configuration, et quels
// runtimes l'Agent annonce à l'Admin.

func agentWith(mut func(*config.AgentConfig)) *config.AgentConfig {
	cfg := &config.AgentConfig{}
	cfg.Docker.Enabled = true
	cfg.Docker.SocketPath = "/var/run/docker.sock"
	mut(cfg)
	return cfg
}

func TestNew_ActivatedSources(t *testing.T) {
	cases := []struct {
		name     string
		mut      func(*config.AgentConfig)
		runtimes []string
		docker   bool
	}{
		{"docker seul", func(c *config.AgentConfig) {}, []string{"docker"}, true},
		{"tout activé", func(c *config.AgentConfig) {
			c.Portainer.Enabled, c.Portainer.URL, c.Portainer.APIKey = true, "https://p:9443", "k"
			c.Kubernetes.Enabled, c.Kubernetes.APIServer = true, "https://127.0.0.1:6443"
		}, []string{"docker", "portainer", "kubernetes"}, true},
		{"docker désactivé", func(c *config.AgentConfig) { c.Docker.Enabled = false }, nil, false},
		{"ancienne config : runtime défini", func(c *config.AgentConfig) {
			c.Docker.Enabled, c.Docker.Runtime = false, "podman"
			c.Docker.SocketPath = "/run/podman/podman.sock"
		}, []string{"podman"}, true},
		{"portainer sans clé API", func(c *config.AgentConfig) {
			c.Docker.Enabled = false
			c.Portainer.Enabled, c.Portainer.URL = true, "https://p:9443"
		}, nil, false},
		{"portainer sans URL", func(c *config.AgentConfig) {
			c.Docker.Enabled = false
			c.Portainer.Enabled, c.Portainer.APIKey = true, "k"
		}, nil, false},
		{"portainer désactivé mais renseigné", func(c *config.AgentConfig) {
			c.Docker.Enabled = false
			c.Portainer.URL, c.Portainer.APIKey = "https://p:9443", "k"
		}, nil, false},
		{"kubernetes seul", func(c *config.AgentConfig) {
			c.Docker.Enabled = false
			c.Kubernetes.Enabled = true
		}, []string{"kubernetes"}, false},
	}
	for _, c := range cases {
		a, err := New(agentWith(c.mut), "")
		if err != nil {
			t.Fatalf("%s : %v", c.name, err)
		}
		if got := a.detectedRuntimes(); !reflect.DeepEqual(got, c.runtimes) {
			t.Errorf("%s : runtimes = %v, attendu %v", c.name, got, c.runtimes)
		}
		if (a.discovery != nil) != c.docker {
			t.Errorf("%s : discovery Docker présente = %v, attendu %v", c.name, a.discovery != nil, c.docker)
		}
	}
}

// Le heartbeat envoie la config au format que l'Admin préremplit ; les secrets sont masqués.
func TestSanitizedAgentConfig_Shape(t *testing.T) {
	cfg := agentWith(func(c *config.AgentConfig) {
		c.ControlPlane.EdgeEndpoint = "http://edge:8000"
		c.Portainer.Enabled, c.Portainer.URL, c.Portainer.APIKey = true, "https://p:9443", "secret-key"
		c.Portainer.PollIntervalS = 30
		c.Portainer.EndpointEdges = map[string]config.EndpointEdgeConf{"prod": {EdgeEndpoint: "http://e2", AuthToken: "tok"}}
	})
	got := sanitizedAgentConfig(cfg)

	portainer := got["portainer"].(map[string]any)
	if portainer["api_key"] != "••••••••" || portainer["url"] != "https://p:9443" || portainer["poll_interval_s"] != 30 {
		t.Errorf("portainer = %v", portainer)
	}
	edges := portainer["endpoint_edges"].(map[string]any)["prod"].(map[string]any)
	if edges["auth_token"] != "••••••••" || edges["edge_endpoint"] != "http://e2" {
		t.Errorf("endpoint_edges = %v", edges)
	}
	docker := got["docker"].(map[string]any)
	if docker["enabled"] != true || docker["socket_path"] != "/var/run/docker.sock" {
		t.Errorf("docker = %v", docker)
	}
	if got["control_plane"].(map[string]any)["edge_endpoint"] != "http://edge:8000" {
		t.Errorf("control_plane = %v", got["control_plane"])
	}
	for _, k := range []string{"secret-key", "tok"} {
		if containsString(got, k) {
			t.Errorf("secret %q exposé", k)
		}
	}
}

func containsString(v any, needle string) bool {
	switch t := v.(type) {
	case string:
		return t == needle
	case map[string]any:
		for _, e := range t {
			if containsString(e, needle) {
				return true
			}
		}
	}
	return false
}

// applyConfigPatch ne doit jamais remplacer un secret enregistré par une valeur vide ou masquée.
func TestApplyConfigPatch_KeepsKnownSecrets(t *testing.T) {
	dir := t.TempDir()
	path := dir + "/agent.json"
	writeFile(t, path, `{"portainer":{"api_key":"keep-me","url":"https://old"},"control_plane":{"auth_token":"tok-keep"}}`)
	patch := `{"portainer":{"api_key":"••••••••","url":"https://new"},"control_plane":{"auth_token":""}}`
	if err := applyConfigPatch(path, []byte(patch)); err != nil {
		t.Fatal(err)
	}
	got := readFile(t, path)
	for _, want := range []string{`"keep-me"`, `"https://new"`, `"tok-keep"`} {
		if !contains(got, want) {
			t.Errorf("%s absent de %s", want, got)
		}
	}
}

func writeFile(t *testing.T, path, content string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func contains(s, sub string) bool { return strings.Contains(s, sub) }
