// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"strings"
)

// Un jeton d'Agent est remis à tout hôte qui s'appaire : il circule en clair entre l'Agent et la passerelle et vit sur
// des machines d'application (accès au socket du runtime). Il ne doit donc ouvrir que ce dont l'Agent a besoin ;
// avant, il passait toute l'API interne — pousser des routes, des certificats, restaurer une sauvegarde, envoyer des
// commandes aux autres Agents.
func agentTokenMayCall(method, path string) bool {
	switch {
	case method == http.MethodPost && (path == "/internal/v1/agent/heartbeat" ||
		path == "/internal/v1/agent/events" ||
		path == "/internal/v1/agent/logs" ||
		path == "/internal/v1/agent/containers"):
		return true
	case method == http.MethodDelete && path == "/internal/v1/agent/containers":
		return true
	case method == http.MethodDelete && strings.HasPrefix(path, "/internal/v1/routes/"):
		id := strings.TrimPrefix(path, "/internal/v1/routes/")
		return isAgentDiscoveredRouteID(id)
	}
	return false
}

// isAgentDiscoveredRouteID : un Agent ne retire que les routes issues de sa découverte, jamais une route configurée
// depuis l'Admin ni une délégation.
func isAgentDiscoveredRouteID(id string) bool {
	for _, p := range []string{"docker:", "docker-host:", "k8s:", "portainer:", "podman:"} {
		if strings.HasPrefix(id, p) {
			return true
		}
	}
	return false
}
