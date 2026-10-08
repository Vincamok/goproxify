// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package sources

import (
	"strings"

	agentdocker "github.com/vincamok/goproxify/internal/agent/docker"
	agentk8s "github.com/vincamok/goproxify/internal/agent/k8s"
	agentportainer "github.com/vincamok/goproxify/internal/agent/portainer"
	"github.com/vincamok/goproxify/internal/modules"
)

// Les trois sources fournies avec GoProxify. Les clés des manifestes sont celles de leur section
// d'agent.json (`docker`, `portainer`, `kubernetes`).
func init() {
	text := func(key, label, placeholder string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindText, Required: required}
	}
	secret := func(key, label string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Kind: modules.KindPassword, Secret: true, Required: required}
	}
	kind := func(key, label, kind string) modules.Field {
		return modules.Field{Key: key, Label: label, Kind: kind}
	}

	Register(modules.Manifest{Type: "docker", Label: "Docker / Podman", Fields: []modules.Field{
		kind("enabled", "Enabled", modules.KindBool),
		text("socket_path", "Socket path", "/var/run/docker.sock", false),
		text("runtime", "Runtime (auto, docker, podman)", "auto", false),
		text("label_prefix", "Label prefix", "goproxify.", false),
		kind("poll_interval_ms", "Poll interval (ms)", modules.KindNumber),
		text("registry_username", "Private registry user", "", false),
		secret("registry_password", "Private registry password", false),
		text("registry_server", "Private registry server", "ghcr.io", false),
	}}, dockerSource)

	Register(modules.Manifest{Type: "portainer", Label: "Portainer", Fields: []modules.Field{
		kind("enabled", "Enabled", modules.KindBool),
		text("url", "Portainer URL", "https://portainer:9443", true),
		secret("api_key", "API key", true),
		kind("poll_interval_s", "Poll interval (s)", modules.KindNumber),
		kind("skip_endpoints", "Endpoints to skip", modules.KindList),
	}}, portainerSource)

	Register(modules.Manifest{Type: "kubernetes", Label: "Kubernetes", Fields: []modules.Field{
		kind("enabled", "Enabled", modules.KindBool),
		text("api_server", "API server (empty = in-cluster)", "https://kubernetes.default.svc", false),
		secret("token", "Bearer token (empty = service account)", false),
		text("ca_cert", "CA certificate (PEM or path)", "", false),
		text("namespace", "Namespace (empty = all)", "", false),
		text("label_prefix", "Label prefix", "goproxify.", false),
	}}, kubernetesSource)
}

// dockerSource : activée par docker.enabled, ou par docker.runtime pour les anciennes configs.
func dockerSource(d Deps) (*Instance, error) {
	cfg := d.Cfg
	if !(cfg.Docker.Enabled || cfg.Docker.Runtime != "") {
		return nil, nil
	}
	disc := agentdocker.NewDiscovery(
		d.Docker,
		cfg.ControlPlane.EdgeEndpoint,
		cfg.ControlPlane.AuthToken,
		cfg.Docker.LabelPrefix,
		cfg.Identity.NodeName,
		d.Net,
		d.Log,
	)
	disc.SetEndpointFunc(d.Edges.Current)
	runtime := "docker"
	if strings.Contains(cfg.Docker.SocketPath, "podman") {
		runtime = "podman"
	}
	var runtimes []string
	if cfg.Docker.SocketPath != "" {
		runtimes = []string{runtime}
	}
	return &Instance{Impl: disc, Start: disc.Start, SetToken: disc.SetToken, Reannounce: disc.ScanAll, Runtimes: runtimes}, nil
}

func portainerSource(d Deps) (*Instance, error) {
	cfg := d.Cfg
	if !(cfg.Portainer.Enabled && cfg.Portainer.URL != "" && cfg.Portainer.APIKey != "") {
		return nil, nil
	}
	epEdges := make(map[string]agentportainer.EndpointEdgeInput, len(cfg.Portainer.EndpointEdges))
	for name, c := range cfg.Portainer.EndpointEdges {
		epEdges[name] = agentportainer.EndpointEdgeInput{EdgeEndpoint: c.EdgeEndpoint, AuthToken: c.AuthToken}
	}
	disc := agentportainer.NewDiscovery(
		agentportainer.NewClient(cfg.Portainer.URL, cfg.Portainer.APIKey),
		cfg.ControlPlane.EdgeEndpoint,
		cfg.ControlPlane.AuthToken,
		cfg.Docker.LabelPrefix,
		cfg.Identity.NodeName,
		cfg.Portainer.PollIntervalS,
		d.Log,
		d.Net,
		cfg.Portainer.SkipEndpoints,
		epEdges,
	)
	disc.SetEndpointFunc(d.Edges.Current)
	return &Instance{Impl: disc, Start: disc.Start, Blocking: true, SetToken: disc.SetToken, Reannounce: disc.Resync, Runtimes: []string{"portainer"}}, nil
}

func kubernetesSource(d Deps) (*Instance, error) {
	if !d.Cfg.Kubernetes.Enabled {
		return nil, nil
	}
	disc, err := agentk8s.New(d.Cfg, d.Log)
	if err != nil {
		return nil, err
	}
	disc.SetEndpointFunc(d.Edges.Current)
	return &Instance{Impl: disc, Start: disc.Start, Blocking: true, SetToken: disc.SetToken, Reannounce: disc.Resync, Runtimes: []string{"kubernetes"}}, nil
}
