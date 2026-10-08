// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"context"
	"errors"
	"io"
	"log/slog"
	"reflect"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/modules"
)

func testDeps(sources map[string]map[string]any) Deps {
	return Deps{
		Cfg: &config.AgentConfig{Sources: sources},
		Log: slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

// consulManifest est une source « ajoutée après coup » : elle n'a aucune section dans AgentConfig,
// sa configuration vient de sources.consul.
var consulManifest = modules.Manifest{Type: "consul", Label: "Consul", Fields: []modules.Field{
	{Key: "url", Label: "URL", Kind: modules.KindText, Required: true},
	{Key: "token", Label: "ACL token", Kind: modules.KindPassword, Secret: true},
}}

func consulFactory(started *[]string) Factory {
	return func(d Deps) (*Instance, error) {
		s := d.Settings("consul")
		if s == nil {
			return nil, nil // non configurée
		}
		return &Instance{
			Start:    func(context.Context) { *started = append(*started, "consul:"+s["url"].(string)) },
			Blocking: true,
			SetToken: func(string) {},
			Runtimes: []string{"consul"},
		}, nil
	}
}

func TestBuild_NewSourceNeedsNoAgentChange(t *testing.T) {
	var started []string
	reg := NewRegistry()
	reg.Register(consulManifest, consulFactory(&started))

	out := Build(reg, testDeps(map[string]map[string]any{"consul": {"url": "http://consul:8500", "token": "t"}}))
	if len(out) != 1 || out[0].Type != "consul" || !reflect.DeepEqual(out[0].Runtimes, []string{"consul"}) {
		t.Fatalf("instances = %+v", out)
	}
	out[0].Start(t.Context())
	if len(started) != 1 || started[0] != "consul:http://consul:8500" {
		t.Fatalf("started = %v", started)
	}
}

func TestBuild_DisabledSourceIsNotAnError(t *testing.T) {
	var started []string
	reg := NewRegistry()
	reg.Register(consulManifest, consulFactory(&started))
	if out := Build(reg, testDeps(nil)); len(out) != 0 {
		t.Fatalf("source non configurée construite : %+v", out)
	}
}

func TestBuild_InvalidSettingsSkipTheSourceOnly(t *testing.T) {
	var started []string
	reg := NewRegistry()
	reg.Register(consulManifest, consulFactory(&started))
	reg.Register(modules.Manifest{Type: "ok", Label: "OK"}, func(Deps) (*Instance, error) { return &Instance{}, nil })

	for name, settings := range map[string]map[string]any{
		"url manquante": {"token": "t"},
		"clé inconnue":  {"url": "http://c", "typo": 1},
	} {
		out := Build(reg, testDeps(map[string]map[string]any{"consul": settings}))
		if len(out) != 1 || out[0].Type != "ok" {
			t.Errorf("%s : instances = %+v (consul doit être ignorée, ok conservée)", name, out)
		}
	}
}

func TestBuild_FailingFactoryDoesNotBlockOthers(t *testing.T) {
	reg := NewRegistry()
	reg.Register(modules.Manifest{Type: "a", Label: "A"}, func(Deps) (*Instance, error) { return nil, errors.New("boom") })
	reg.Register(modules.Manifest{Type: "b", Label: "B"}, func(Deps) (*Instance, error) { return &Instance{}, nil })
	reg.Register(modules.Manifest{Type: "c", Label: "C"}, func(Deps) (*Instance, error) { return &Instance{}, nil })
	out := Build(reg, testDeps(nil))
	if len(out) != 2 || out[0].Type != "b" || out[1].Type != "c" {
		t.Fatalf("instances = %+v (ordre de déclaration attendu)", out)
	}
}

func TestBuiltinManifests(t *testing.T) {
	var got []string
	for _, m := range Manifests() {
		got = append(got, m.Type)
	}
	if !reflect.DeepEqual(got, []string{"docker", "portainer", "kubernetes"}) {
		t.Fatalf("sources intégrées = %v", got)
	}
}

// Les champs secrets des manifestes alimentent la protection des secrets lors d'un correctif de
// configuration : avant, une liste écrite à la main oubliait le jeton Kubernetes et le mot de passe
// du registre Docker.
func TestSecretKeys(t *testing.T) {
	got := BuiltinSecretKeys()
	for _, want := range []string{"api_key", "token", "registry_password"} {
		found := false
		for _, k := range got {
			found = found || k == want
		}
		if !found {
			t.Errorf("%s absent de %v", want, got)
		}
	}
	for _, k := range got {
		if strings.Contains(k, "url") || k == "enabled" {
			t.Errorf("%s n'est pas un secret", k)
		}
	}
}

func TestView_MasksSecretsAndSkipsMissingKeys(t *testing.T) {
	got := View(consulManifest, map[string]any{"url": "http://c", "token": "s3cret", "inconnu": "x"})
	if got["url"] != "http://c" || got["token"] != modules.Masque {
		t.Fatalf("vue = %v", got)
	}
	if _, ok := got["inconnu"]; ok {
		t.Fatal("clé hors manifeste exposée")
	}
	if got := View(consulManifest, map[string]any{"token": ""}); got["token"] != "" {
		t.Fatalf("secret vide : rien à masquer, got %v", got["token"])
	}
	if got := View(consulManifest, map[string]any{}); len(got) != 0 {
		t.Fatalf("section vide : %v", got)
	}
}

func TestDockerSource_RuntimeNamedAfterSocket(t *testing.T) {
	for socket, want := range map[string][]string{
		"/var/run/docker.sock":    {"docker"},
		"/run/podman/podman.sock": {"podman"},
		"":                        nil,
	} {
		cfg := &config.AgentConfig{}
		cfg.Docker.Enabled, cfg.Docker.SocketPath = true, socket
		d := testDeps(nil)
		d.Cfg = cfg
		d.Edges = nil
		inst := dockerInstance(t, d)
		if !reflect.DeepEqual(inst.Runtimes, want) {
			t.Errorf("socket %q : runtimes = %v, attendu %v", socket, inst.Runtimes, want)
		}
		if inst.Blocking || inst.SetToken == nil {
			t.Errorf("Docker démarre sans bloquer et reçoit le jeton : %+v", inst)
		}
	}
}

func dockerInstance(t *testing.T, d Deps) *Instance {
	t.Helper()
	inst, err := dockerSource(d)
	if err != nil || inst == nil {
		t.Fatalf("dockerSource : %v, %v", inst, err)
	}
	return inst
}
