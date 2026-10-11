// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"os"
	"strings"

	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
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

// Avec GPX_AGENT_BIND_IDENTITY=true, un Agent ne peut agir qu'au nom de l'Agent dont le jeton porte le nom : sans cela,
// n'importe quel Agent pouvait se déclarer un autre dans son heartbeat (et faire purger les routes de celui-ci) ou
// annoncer des routes à son nom. Désactivé par défaut : un jeton émis sous un autre nom que l'identité actuelle de
// l'Agent (renommage après l'appairage) serait refusé jusqu'à un nouvel appairage ; le chart l'active.
func agentIdentityStrict() bool { return os.Getenv("GPX_AGENT_BIND_IDENTITY") == "true" }

// agentMayActAs répond 403 et renvoie false si le jeton d'Agent présenté n'est pas celui de l'Agent « claimed ».
func (s *Server) agentMayActAs(w http.ResponseWriter, r *http.Request, claimed string) bool {
	if !agentIdentityStrict() || s.tokenStore == nil {
		return true
	}
	bearer := strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer ")
	role, ok, err := s.tokenStore.RoleOf(bearer)
	if err != nil || !ok || role != edgetokens.RoleAgent {
		return true
	}
	if claimed != "" && s.tokenStore.NameOf(bearer) == claimed {
		return true
	}
	if s.log != nil {
		s.log.Warn("agent: jeton utilisé pour un autre Agent, refusé", "annoncé", claimed, "path", r.URL.Path)
	}
	http.Error(w, "403 Forbidden", http.StatusForbidden)
	return false
}
