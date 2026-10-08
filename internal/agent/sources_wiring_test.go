// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"context"
	"os"
	"reflect"
	"strings"
	"testing"
	"time"

	agentsources "github.com/vincamok/goproxify/internal/agent/sources"
	"github.com/vincamok/goproxify/internal/config"
)

func fakeSource(typ string, blocking bool, log *[]string) *agentsources.Instance {
	return &agentsources.Instance{
		Type:     typ,
		Blocking: blocking,
		Start:    func(context.Context) { *log = append(*log, "start:"+typ) },
		SetToken: func(tok string) { *log = append(*log, "token:"+typ+"="+tok) },
		Runtimes: []string{typ},
	}
}

// Le jeton obtenu à l'appairage doit atteindre toutes les sources, Kubernetes comprise : elle ne le
// recevait jamais, et un agent appairé à l'exécution lui faisait pousser ses routes sans jeton.
func TestSetSourcesToken_ReachesEverySource(t *testing.T) {
	var log []string
	a := &Agent{sources: []*agentsources.Instance{
		fakeSource("docker", false, &log), fakeSource("portainer", true, &log), fakeSource("kubernetes", true, &log),
	}}
	a.sources = append(a.sources, &agentsources.Instance{Type: "sans-jeton"}) // SetToken nil : ignoré
	a.setSourcesToken("T1")
	want := []string{"token:docker=T1", "token:portainer=T1", "token:kubernetes=T1"}
	if !reflect.DeepEqual(log, want) {
		t.Fatalf("log = %v", log)
	}
}

// Les sources qui rendent la main démarrent avant celles qui bouclent (qui partent en goroutine).
func TestStartSources_SplitsBlockingAndNot(t *testing.T) {
	var log []string
	a := &Agent{sources: []*agentsources.Instance{
		fakeSource("docker", false, &log), fakeSource("portainer", true, &log),
	}}
	a.startSources(context.Background(), false)
	if !reflect.DeepEqual(log, []string{"start:docker"}) {
		t.Fatalf("après le premier lot : %v", log)
	}
}

func TestDetectedRuntimes_FromSources(t *testing.T) {
	var log []string
	a := &Agent{sources: []*agentsources.Instance{fakeSource("docker", false, &log), fakeSource("consul", true, &log)}}
	if got := a.detectedRuntimes(); !reflect.DeepEqual(got, []string{"docker", "consul"}) {
		t.Fatalf("runtimes = %v", got)
	}
	if got := (&Agent{}).detectedRuntimes(); got != nil {
		t.Fatalf("sans source : %v", got)
	}
}

func TestSanitizedAgentConfig_ExposesKubernetesWithoutSecrets(t *testing.T) {
	cfg := agentWith(func(c *config.AgentConfig) {
		c.Kubernetes.Enabled, c.Kubernetes.APIServer = true, "https://k8s:6443"
		c.Kubernetes.Token, c.Kubernetes.Namespace = "kube-secret-token", "prod"
		c.Sources = map[string]map[string]any{"consul": {"url": "http://c", "token": "consul-secret"}}
	})
	got := sanitizedAgentConfig(cfg)
	k := got["kubernetes"].(map[string]any)
	if k["enabled"] != true || k["api_server"] != "https://k8s:6443" || k["namespace"] != "prod" || k["token"] != "••••••••" {
		t.Fatalf("kubernetes = %v", k)
	}
	for _, leaked := range []string{"kube-secret-token", "consul-secret"} {
		if containsString(got, leaked) {
			t.Errorf("secret %q exposé", leaked)
		}
	}
	// Une source sans manifeste dans le registre de l'Agent n'est pas exposée.
	if s, ok := got["sources"]; ok && len(s.(map[string]any)) != 0 {
		t.Errorf("sources = %v", s)
	}
}

// Le correctif de configuration envoyé par l'Admin ne doit jamais écraser un secret enregistré,
// y compris ceux que l'ancienne liste de noms de clés oubliait.
func TestApplyConfigPatch_KeepsManifestDeclaredSecrets(t *testing.T) {
	path := t.TempDir() + "/agent.json"
	if err := os.WriteFile(path, []byte(`{"kubernetes":{"token":"kube-keep","namespace":"old"},"docker":{"registry_password":"reg-keep","registry_server":"old"}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	patch := `{"kubernetes":{"token":"••••••••","namespace":"new"},"docker":{"registry_password":"","registry_server":"ghcr.io"}}`
	if err := applyConfigPatch(path, []byte(patch)); err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(path)
	got := string(b)
	for _, want := range []string{`"kube-keep"`, `"reg-keep"`, `"new"`, `"ghcr.io"`} {
		if !strings.Contains(got, want) {
			t.Errorf("%s absent de %s", want, got)
		}
	}
	if strings.Contains(got, "••••••••") {
		t.Errorf("le masque a été enregistré : %s", got)
	}
}

func TestStructToMap(t *testing.T) {
	cfg := &config.AgentConfig{}
	cfg.Kubernetes.Enabled, cfg.Kubernetes.CACert = true, "pem"
	m := structToMap(cfg.Kubernetes)
	if m["enabled"] != true || m["ca_cert"] != "pem" || len(m) != 6 {
		t.Fatalf("map = %v", m)
	}
}

// Après une bascule vers un autre membre du groupe HA (ou une reconnexion), TOUTES les sources
// republient leur état, pas seulement Docker : Portainer et Kubernetes restaient attachées à la
// passerelle tombée et, pour Kubernetes, un Service inchangé n'est jamais renvoyé.
func TestReannounceSources_ReachesEverySourceThatHasOne(t *testing.T) {
	got := make(chan string, 4)
	mk := func(typ string, withReannounce bool) *agentsources.Instance {
		i := &agentsources.Instance{Type: typ}
		if withReannounce {
			i.Reannounce = func(context.Context) { got <- typ }
		}
		return i
	}
	a := &Agent{sources: []*agentsources.Instance{mk("docker", true), mk("portainer", true), mk("kubernetes", true), mk("passive", false)}}
	if !a.hasReannounce() {
		t.Fatal("hasReannounce")
	}
	a.reannounceSources(context.Background())

	seen := map[string]bool{}
	for i := 0; i < 3; i++ {
		select {
		case typ := <-got:
			seen[typ] = true
		case <-time.After(3 * time.Second):
			t.Fatalf("réannonces reçues : %v", seen)
		}
	}
	if !seen["docker"] || !seen["portainer"] || !seen["kubernetes"] {
		t.Fatalf("réannonces = %v", seen)
	}
	select {
	case typ := <-got:
		t.Fatalf("réannonce inattendue de %s", typ)
	case <-time.After(100 * time.Millisecond):
	}

	if (&Agent{sources: []*agentsources.Instance{mk("passive", false)}}).hasReannounce() {
		t.Fatal("aucune source ne réannonce")
	}
}

func TestBuiltinSources_AllReannounceAndFollowTheGateway(t *testing.T) {
	cfg := agentWith(func(c *config.AgentConfig) {
		c.Portainer.Enabled, c.Portainer.URL, c.Portainer.APIKey = true, "https://p:9443", "k"
		c.Kubernetes.Enabled, c.Kubernetes.APIServer = true, "https://127.0.0.1:6443"
	})
	a, err := New(cfg, "")
	if err != nil {
		t.Fatal(err)
	}
	if len(a.sources) != 3 {
		t.Fatalf("sources = %d", len(a.sources))
	}
	for _, s := range a.sources {
		if s.Reannounce == nil {
			t.Errorf("%s n'a pas de réannonce", s.Type)
		}
	}
}
