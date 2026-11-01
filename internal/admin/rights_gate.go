// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
)

// readPermission dit quelle permission du catalogue exige une lecture des services dont les accès d'équipe sont
// appliqués (logs, certificats, alertes, métriques ; ADR 0022, livraison 4). Une lecture qu'aucune ligne ne reconnaît
// est refusée à un compte sans droit d'administrateur : on oublie une route, elle reste fermée. Les écritures ne passent
// pas par ici : l'enveloppe qui suit les réserve encore aux administrateurs.
func readPermission(r *http.Request) (string, bool) {
	if r.Method != http.MethodGet && r.Method != http.MethodHead {
		return "", false
	}
	path := strings.TrimSuffix(r.URL.Path, "/")
	has := func(prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }
	switch {
	case has("/api/v1/logs"):
		switch strings.TrimPrefix(strings.TrimPrefix(path, "/api/v1/logs"), "/") {
		case "", "facets", "histogram", "live", "correlate":
			return "logs:read", true
		case "export":
			return "logs:export", true
		case "settings":
			return "logs_settings:read", true
		}
	case has("/api/v1/certs"):
		rest := strings.TrimPrefix(strings.TrimPrefix(path, "/api/v1/certs"), "/")
		switch {
		case rest == "" || rest == "acme-monitor" || strings.HasSuffix(rest, "/pem"):
			return "certs:read", true
		case strings.Contains(rest, "/deploy-targets") || strings.Contains(rest, "/pull-tokens"):
			return "certs:deploy", true
		}
	case has("/api/v1/cert-deploy-types"):
		return "certs:read", true
	case has("/api/v1/alert-events"), has("/api/v1/alert-rules"):
		return "alerts:read", true
	case has("/api/v1/alert-channels"), has("/api/v1/alert-channel-types"):
		return "alert_channels:read", true
	case has("/api/v1/metrics"), has("/api/v1/prism"):
		return "dashboard:read", true
	}
	return "unmapped", true
}
