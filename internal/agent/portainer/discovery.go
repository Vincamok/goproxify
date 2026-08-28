// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portainer

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/agent/docker"
)

// Discovery découvre les conteneurs sur tous les endpoints Portainer
// et les rapporte à l'Administration Goproxify.
type Discovery struct {
	client        *Client
	adminEndpoint string
	authToken     string
	labelPrefix   string
	agentName     string
	pollInterval  time.Duration
	log           *slog.Logger

	mu       sync.Mutex
	prevSeen map[string]bool // clés "endpointID:containerID" du scan précédent
}

// NewDiscovery crée une Discovery Portainer.
func NewDiscovery(client *Client, adminEndpoint, authToken, labelPrefix, agentName string,
	pollIntervalS int, log *slog.Logger) *Discovery {
	if pollIntervalS <= 0 {
		pollIntervalS = 30
	}
	return &Discovery{
		client:        client,
		adminEndpoint: adminEndpoint,
		authToken:     authToken,
		labelPrefix:   labelPrefix,
		agentName:     agentName,
		pollInterval:  time.Duration(pollIntervalS) * time.Second,
		log:           log,
	}
}

// SetToken met à jour le token d'authentification vers le Core.
func (d *Discovery) SetToken(token string) {
	d.mu.Lock()
	d.authToken = token
	d.mu.Unlock()
}

// Start lance la boucle de découverte : scan initial puis polling périodique.
// Portainer ne fournit pas de stream d'événements multi-endpoint, on poll donc.
func (d *Discovery) Start(ctx context.Context) {
	d.scan(ctx)
	ticker := time.NewTicker(d.pollInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			d.scan(ctx)
		}
	}
}

// scan liste tous les endpoints puis tous les conteneurs de chacun.
func (d *Discovery) scan(ctx context.Context) {
	endpoints, err := d.client.ListEndpoints(ctx)
	if err != nil {
		d.log.Error("portainer: liste endpoints", "err", err)
		return
	}

	seen := map[string]bool{}

	d.log.Info("portainer: scan", "endpoints", len(endpoints))

	for _, ep := range endpoints {
		containers, err := d.client.ListContainers(ctx, ep.ID)
		if err != nil {
			d.log.Warn("portainer: liste containers", "endpoint", ep.Name, "err", err)
			continue
		}
		d.log.Info("portainer: endpoint scanné", "endpoint", ep.Name, "containers", len(containers))
		epHost := endpointHost(ep.URL)
		for _, c := range containers {
			firstNet, firstIP := "", ""
			for name, net := range c.NetworkSettings.Networks {
				firstNet = name
				firstIP = net.IPAddress
				break
			}
			firstName := ""
			if len(c.Names) > 0 {
				firstName = c.Names[0]
			}
			specs := d.resolveSpecs(c, firstNet, firstName, firstIP, epHost)
			if len(specs) == 0 {
				d.log.Debug("portainer: container sans labels goproxify", "container", firstName, "image", c.Image)
				continue
			}
			key := fmt.Sprintf("%d:%s", ep.ID, c.ID)
			seen[key] = true
			for _, spec := range specs {
				d.report(ctx, ep, spec)
			}
		}
	}

	d.mu.Lock()
	prev := d.prevSeen
	d.prevSeen = seen
	d.mu.Unlock()

	for key := range prev {
		if !seen[key] {
			d.removeByKey(ctx, key)
		}
	}
}

// removeByKey supprime une route portainer disparue identifiée par "endpointID:containerID".
func (d *Discovery) removeByKey(ctx context.Context, key string) {
	parts := strings.SplitN(key, ":", 2)
	if len(parts) != 2 {
		return
	}
	containerID := parts[1]
	shortID := containerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	d.mu.Lock()
	token := d.authToken
	d.mu.Unlock()

	payload, _ := json.Marshal(map[string]any{
		"container_id": shortID,
		"name":         key,
		"source":       "portainer",
	})
	url := d.adminEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, url, bytes.NewReader(payload))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.log.Warn("portainer: suppression route", "key", key, "err", err)
		return
	}
	resp.Body.Close()
	d.log.Info("portainer: route retirée", "key", key)
}

// endpointHost extrait le hostname d'une URL d'endpoint Portainer.
// Retourne "" pour les endpoints locaux (unix://).
func endpointHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	u, err := url.Parse(rawURL)
	if err != nil || u.Scheme == "unix" {
		return ""
	}
	return u.Hostname()
}

// firstPublishedTCPPort retourne le premier port TCP publié (port hôte) du conteneur.
func firstPublishedTCPPort(ports []ContainerPort) int {
	for _, p := range ports {
		if strings.EqualFold(p.Type, "tcp") && p.PublicPort > 0 {
			return p.PublicPort
		}
	}
	return 0
}

// resolveSpecs construit les ProxySpec en résolvant l'IP/port correctement selon l'endpoint.
// Pour les endpoints distants (TCP), utilise l'hôte de l'endpoint + port publié plutôt que
// l'IP interne du conteneur qui n'est pas routable depuis le Core.
func (d *Discovery) resolveSpecs(c Container, firstNet, firstName, containerIP, epHost string) []*docker.ProxySpec {
	labels := c.Labels

	// Pour les endpoints TCP distants : remplacer l'IP interne par l'hôte de l'endpoint
	if epHost != "" && labels[docker.LabelBackendURL] == "" && labels[docker.LabelIP] == "" {
		clone := make(map[string]string, len(labels)+2)
		for k, v := range labels {
			clone[k] = v
		}
		clone[docker.LabelIP] = epHost
		if clone[docker.LabelPort] == "" {
			if pub := firstPublishedTCPPort(c.Ports); pub > 0 {
				clone[docker.LabelPort] = strconv.Itoa(pub)
			}
		}
		labels = clone
	}

	return docker.ParseLabelsMulti(c.ID, firstName, c.Image, firstNet, labels, nil, containerIP)
}

// report envoie la config proxy vers l'Administration.
func (d *Discovery) report(ctx context.Context, ep Endpoint, spec *docker.ProxySpec) {
	containerName := strings.TrimPrefix(spec.ContainerName, "/")
	shortID := spec.ContainerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}
	payload := map[string]any{
		"id":           fmt.Sprintf("portainer:%d:%s:%s", ep.ID, shortID, spec.Host),
		"host":         spec.Host,
		"aliases":      spec.Aliases,
		"paths":        spec.Paths,
		"route_type":   spec.Type,
		"backends":     []string{spec.BackendURL},
		"tls_enabled":  spec.TLS,
		"passthrough":  spec.Passthrough,
		"source":       "portainer",
		"container_id": spec.ContainerID,
		"endpoint_id":  ep.ID,
		"endpoint_name": ep.Name,
		"agent_name":   d.agentName,
		"role":         spec.Role,
	}
	if spec.Role == docker.RoleCanary {
		payload["canary_weight"] = spec.CanaryWeight
	}
	docker.AttachSecurityPayload(payload, spec)

	d.mu.Lock()
	token := d.authToken
	d.mu.Unlock()

	body, _ := json.Marshal(payload)
	url := d.adminEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, url, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.log.Warn("portainer: report vers Admin", "host", spec.Host, "container", containerName, "err", err)
		return
	}
	defer resp.Body.Close()
	d.log.Info("portainer: proxy rapporté", "host", spec.Host, "endpoint", ep.Name, "status", resp.StatusCode)
}
