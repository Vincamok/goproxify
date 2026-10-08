// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"

	agentsources "github.com/vincamok/goproxify/internal/agent/sources"
)

// DiscoverySourcesHandler GET /api/v1/discovery-sources : manifestes des sources de découverte de
// l'Agent (Docker/Podman, Portainer, Kubernetes…) — champs de configuration, secrets, requis. Les
// sources sont des modules du registre commun (ADR 0007).
type DiscoverySourcesHandler struct{}

func (DiscoverySourcesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, agentsources.Manifests())
}
