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

// netManager est l'interface minimale pour connecter le Core à un réseau Docker.
type netManager interface {
	ConnectCoreToNetwork(ctx context.Context, networkID string) error
}

// endpointCoreConf est la config d'un Core alternatif pour un endpoint Portainer.
type endpointCoreConf struct {
	coreEndpoint string
	authToken    string
}

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
	netMgr        netManager // connecte le Core aux réseaux Docker locaux (nil = désactivé)
	skipEndpoints map[string]bool
	endpointCores map[string]endpointCoreConf // endpoint name (lowercase) → Core alternatif

	mu       sync.Mutex
	prevSeen map[string]bool // clés "endpointID:containerID" du scan précédent
}

// EndpointCoreInput est utilisé par l'appelant pour configurer les Cores alternatifs.
type EndpointCoreInput struct {
	CoreEndpoint string
	AuthToken    string
}

// NewDiscovery crée une Discovery Portainer.
// netMgr peut être nil ; s'il est fourni, le Core est connecté aux réseaux Docker
// des conteneurs découverts sur les endpoints locaux (socket unix).
func NewDiscovery(client *Client, adminEndpoint, authToken, labelPrefix, agentName string,
	pollIntervalS int, log *slog.Logger, netMgr netManager,
	skipEndpoints []string, epCores map[string]EndpointCoreInput) *Discovery {
	if pollIntervalS <= 0 {
		pollIntervalS = 30
	}
	skip := make(map[string]bool, len(skipEndpoints))
	for _, name := range skipEndpoints {
		skip[strings.ToLower(name)] = true
	}
	cores := make(map[string]endpointCoreConf, len(epCores))
	for name, c := range epCores {
		cores[strings.ToLower(name)] = endpointCoreConf{
			coreEndpoint: c.CoreEndpoint,
			authToken:    c.AuthToken,
		}
	}
	return &Discovery{
		client:        client,
		adminEndpoint: adminEndpoint,
		authToken:     authToken,
		labelPrefix:   labelPrefix,
		agentName:     agentName,
		pollInterval:  time.Duration(pollIntervalS) * time.Second,
		log:           log,
		netMgr:        netMgr,
		skipEndpoints: skip,
		endpointCores: cores,
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
		if d.skipEndpoints[strings.ToLower(ep.Name)] {
			d.log.Debug("portainer: endpoint ignoré (skip_endpoints)", "endpoint", ep.Name)
			continue
		}
		containers, err := d.client.ListContainers(ctx, ep.ID)
		if err != nil {
			d.log.Warn("portainer: liste containers", "endpoint", ep.Name, "err", err)
			continue
		}
		d.log.Info("portainer: endpoint scanné", "endpoint", ep.Name, "containers", len(containers))
		epHost := endpointHost(ep.URL)
		isLocal := epHost == "" || isLocalHost(epHost)
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
			// Endpoint local (socket unix) : connecter le Core au réseau Docker du conteneur
			// pour que l'IP interne soit joignable, comme le fait la découverte Docker locale.
			if isLocal && d.netMgr != nil && firstNet != "" {
				if err := d.netMgr.ConnectCoreToNetwork(ctx, firstNet); err != nil {
					d.log.Warn("portainer: connexion Core au réseau", "network", firstNet, "err", err)
				}
			}
			key := fmt.Sprintf("%d:%s:%s", ep.ID, ep.Name, c.ID)
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

// removeByKey supprime une route portainer disparue identifiée par "endpointID:endpointName:containerID".
func (d *Discovery) removeByKey(ctx context.Context, key string) {
	// Format : "endpointID:endpointName:containerID"
	// Compat ancien format "endpointID:containerID" (sans endpointName).
	parts := strings.SplitN(key, ":", 3)
	var epName, containerID string
	switch len(parts) {
	case 3:
		epName = parts[1]
		containerID = parts[2]
	case 2:
		containerID = parts[1]
	default:
		return
	}
	shortID := containerID
	if len(shortID) > 12 {
		shortID = shortID[:12]
	}

	coreEndpoint, token := d.coreFor(epName)

	payload, _ := json.Marshal(map[string]any{
		"container_id": shortID,
		"name":         key,
		"source":       "portainer",
	})
	reqURL := coreEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodDelete, reqURL, bytes.NewReader(payload))
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

// coreFor retourne l'endpoint et le token du Core à utiliser pour un endpoint Portainer donné.
// Si aucun Core alternatif n'est configuré pour cet endpoint, retourne le Core par défaut.
func (d *Discovery) coreFor(epName string) (coreEndpoint, token string) {
	if epName != "" {
		if conf, ok := d.endpointCores[strings.ToLower(epName)]; ok {
			return conf.coreEndpoint, conf.authToken
		}
	}
	d.mu.Lock()
	tok := d.authToken
	d.mu.Unlock()
	return d.adminEndpoint, tok
}

// endpointHost extrait le hostname d'une URL d'endpoint Portainer.
// Retourne "" pour les endpoints locaux (unix://, npipe://).
// Portainer stocke parfois les URLs sans scheme (ex : "192.168.1.100:9001") ;
// on normalise avant parsing pour éviter que url.Parse interprète l'hôte comme scheme.
func endpointHost(rawURL string) string {
	if rawURL == "" {
		return ""
	}
	normalized := rawURL
	if !strings.Contains(rawURL, "://") {
		normalized = "tcp://" + rawURL
	}
	u, err := url.Parse(normalized)
	if err != nil || u.Scheme == "unix" || u.Scheme == "npipe" {
		return ""
	}
	return u.Hostname()
}

// isLocalHost retourne true si l'hôte est localhost ou une adresse de loopback.
func isLocalHost(h string) bool {
	return h == "localhost" || h == "127.0.0.1" || h == "::1"
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

// firstPrivateTCPPort retourne le premier port TCP interne du conteneur (PrivatePort).
// Utilisé pour les endpoints locaux où l'IP interne est directement accessible.
func firstPrivateTCPPort(ports []ContainerPort) int {
	for _, p := range ports {
		if strings.EqualFold(p.Type, "tcp") && p.PrivatePort > 0 {
			return p.PrivatePort
		}
	}
	return 0
}

// resolveSpecs construit les ProxySpec en résolvant l'IP/port correctement selon l'endpoint.
//
// Stratégie de résolution du backend :
//   - Si goproxify.backend ou goproxify.ip est posé dans les labels → priorité absolue (déjà géré par ParseLabelsMulti)
//   - Endpoint TCP distant (epHost non vide) → utiliser epHost + premier port publié
//     (l'IP interne Docker du conteneur distant n'est pas routable depuis le Core)
//   - Endpoint local (unix:// ou epHost vide) → passer containerIP vide pour que
//     ParseLabelsMulti tombe sur le nom du conteneur, résolvable via DNS Docker
func (d *Discovery) resolveSpecs(c Container, firstNet, firstName, containerIP, epHost string) []*docker.ProxySpec {
	labels := c.Labels

	if epHost != "" && !isLocalHost(epHost) && labels[docker.LabelBackendURL] == "" && labels[docker.LabelIP] == "" {
		// Endpoint TCP distant : l'IP interne Docker n'est pas routable depuis le Core.
		// Utiliser l'hôte de l'endpoint Portainer + premier port TCP publié.
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
		return docker.ParseLabelsMulti(c.ID, firstName, c.Image, firstNet, clone, nil, "")
	}

	// Endpoint local (unix:// ou TCP localhost) : garder l'IP interne du conteneur.
	// Le Core doit être dans le même réseau Docker pour la joindre.
	// Si aucun label de port, utiliser PrivatePort (port applicatif du conteneur).
	if labels[docker.LabelBackendURL] == "" && labels[docker.LabelPort] == "" {
		if priv := firstPrivateTCPPort(c.Ports); priv > 0 {
			clone := make(map[string]string, len(labels)+1)
			for k, v := range labels {
				clone[k] = v
			}
			clone[docker.LabelPort] = strconv.Itoa(priv)
			return docker.ParseLabelsMulti(c.ID, firstName, c.Image, firstNet, clone, nil, containerIP)
		}
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

	coreEndpoint, token := d.coreFor(ep.Name)

	body, _ := json.Marshal(payload)
	reqURL := coreEndpoint + "/internal/v1/agent/containers"
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, reqURL, bytes.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		d.log.Warn("portainer: report vers Admin", "host", spec.Host, "container", containerName, "err", err)
		return
	}
	defer resp.Body.Close()
	d.log.Info("portainer: proxy rapporté", "host", spec.Host, "backend", spec.BackendURL, "endpoint", ep.Name, "status", resp.StatusCode)
}
