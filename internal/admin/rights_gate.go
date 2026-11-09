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
	case has("/api/v1/audit"):
		return "audit:read", true
	case has("/api/v1/snippets"), has("/api/v1/detector-types"):
		return "snippets:read", true
	case has("/api/v1/ip-profiles"):
		return "ip_profiles:read", true
	}
	return "unmapped", true
}

// operatePermission dit quelle permission du catalogue exige une requête — lecture ou écriture — des services dont les
// écritures sont ouvertes aux accès d'équipe : alertes, certificats et domaines (ADR 0022, livraison 4). Les handlers
// jugent ensuite l'objet visé (hôte, domaine de la règle…). Ce qu'aucune ligne ne reconnaît est refusé à un
// non-administrateur : une route ajoutée sans permission reste fermée.
func operatePermission(r *http.Request) (string, bool) {
	path := strings.TrimSuffix(r.URL.Path, "/")
	has := func(prefix string) bool { return path == prefix || strings.HasPrefix(path, prefix+"/") }
	read := r.Method == http.MethodGet || r.Method == http.MethodHead
	switch {
	case has("/api/v1/alert-events"):
		if read {
			return "alerts:read", true
		}
		if r.Method == http.MethodPost && strings.HasSuffix(path, "/ack") {
			return "alerts:ack", true
		}
	case has("/api/v1/alert-rules"):
		if read {
			return "alerts:read", true
		}
		return "alerts:rules", true
	case has("/api/v1/alert-channels"):
		if read {
			return "alert_channels:read", true
		}
		if r.Method == http.MethodPost && strings.HasSuffix(path, "/test") {
			return "alert_channels:test", true
		}
		return "alert_channels:manage", true
	case has("/api/v1/alert-channel-types"):
		if read {
			return "alert_channels:read", true
		}
	case has("/api/v1/certs"):
		rest := strings.TrimPrefix(strings.TrimPrefix(path, "/api/v1/certs"), "/")
		// Jetons de récupération : ils exposent le certificat et sa clé (case certs:export_key) ; cibles de déploiement :
		// elles exécutent (webhook, ssh_exec) — case certs:deploy, en lecture comme en écriture.
		if segments := strings.Split(rest, "/"); len(segments) >= 2 {
			switch segments[1] {
			case "pull-tokens":
				return "certs:export_key", true
			case "deploy-targets":
				return "certs:deploy", true
			}
		}
		if read {
			return readPermission(r)
		}
		if rest == "" || rest == "import" || (r.Method == http.MethodDelete && !strings.Contains(rest, "/")) {
			return "certs:manage", true
		}
	case has("/api/v1/domains"):
		if read {
			return "domains:read", true
		}
		return "domains:manage", true
	}
	return "unmapped", true
}

// Les trois tables suivantes donnent la permission d'une requête du portail Access, de la sécurité réseau et de
// l'automatisation. Ces services s'appliquent à toute la plateforme (le portail et les flux n'ont pas encore de
// périmètre par groupe) : la garde exige un accès sans critère. Ce qu'une table ne reconnaît pas est refusé à un
// non-administrateur.

func isRead(r *http.Request) bool { return r.Method == http.MethodGet || r.Method == http.MethodHead }

func pathParts(r *http.Request, prefix string) []string {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, prefix), "/")
	if rest == "" {
		return nil
	}
	return strings.Split(rest, "/")
}

func readOrManage(r *http.Request, read, manage string) (string, bool) {
	if isRead(r) {
		return read, true
	}
	return manage, true
}

// portalPermission : les huit sous-services du portail (ADR 0022, annexe §2.5).
func portalPermission(r *http.Request) (string, bool) {
	if strings.HasPrefix(r.URL.Path, "/api/v1/portal-page-templates") {
		return readOrManage(r, "portal_templates:read", "portal_templates:manage")
	}
	parts := pathParts(r, "/api/v1/portal")
	if len(parts) == 0 {
		return readOrManage(r, "portal_templates:read", "portal_templates:manage")
	}
	switch parts[0] {
	case "users", "groups":
		return readOrManage(r, "portal_users:read", "portal_users:manage")
	case "destinations", "destination-groups", "dest-candidates":
		return readOrManage(r, "portal_catalog:read", "portal_catalog:manage")
	case "logins":
		// Les logins préconfigurés portent des secrets scellés : les créer, modifier ou supprimer exige la permission explicite.
		if isRead(r) {
			return "portal_catalog:read", true
		}
		return "portal_catalog:logins", true
	case "dest-sources":
		// Lire les sources (secrets masqués) et demander un passage relèvent du catalogue ; les créer, les modifier, les
		// supprimer et les essayer exigent la permission explicite : ils manipulent des identifiants d'API.
		if isRead(r) || (len(parts) == 3 && parts[2] == "sync") {
			return readOrManage(r, "portal_catalog:read", "portal_catalog:manage")
		}
		return "portal_catalog:sources", true
	case "policy":
		return readOrManage(r, "portal_policies:read", "portal_policies:manage")
	case "audit":
		if isRead(r) {
			return "portal_audit:read", true
		}
	case "access-requests":
		return readOrManage(r, "portal_requests:read", "portal_requests:decide")
	case "recordings":
		switch {
		case r.Method == http.MethodDelete:
			return "portal_recordings:delete", true
		case isRead(r) && len(parts) == 1:
			return "portal_recordings:list", true
		case isRead(r):
			return "portal_recordings:replay", true
		}
	case "sessions":
		switch {
		case isRead(r) && len(parts) >= 3 && parts[len(parts)-1] == "watch":
			return "portal_sessions:observe", true
		case isRead(r):
			return "portal_sessions:read", true
		default:
			return "portal_sessions:cut", true
		}
	case "enabled", "push", "config":
		return readOrManage(r, "portal_templates:read", "portal_templates:manage")
	}
	return "unmapped", true
}

// securityPermission : la sécurité réseau (bannissements, menaces, CVE, traçage d'IP). Les moteurs adaptatifs, la
// surface applicative, la surveillance des domaines et les réglages (flotte, CrowdSec, WAF, objectifs) restent aux
// administrateurs.
func securityPermission(r *http.Request) (string, bool) {
	parts := pathParts(r, "/api/v1/security")
	if len(parts) == 0 {
		return readOrManage(r, "netsec:read", "unmapped")
	}
	switch parts[0] {
	case "overview", "threats", "cves", "headers", "timeline", "ip-timeline":
		if isRead(r) {
			return "netsec:read", true
		}
		if parts[0] == "cves" && r.Method == http.MethodPatch {
			return "netsec:respond", true
		}
	case "ip-trace":
		if isRead(r) {
			return "netsec:analyse", true
		}
	case "attack-ref":
		return readOrManage(r, "attack_ref:read", "attack_ref:write")
	case "waf-config":
		return readOrManage(r, "engines:read", "engines:tune")
	case "threat-config":
		switch {
		case len(parts) == 1:
			return readOrManage(r, "engines:read", "engines:tune")
		case parts[1] == "suggestions" && isRead(r):
			return "engines:read", true
		case (parts[1] == "simulate" || parts[1] == "calibrate") && r.Method == http.MethodPost:
			return "engines:simulate", true
		}
	case "threat-references":
		if isRead(r) {
			return "engines:read", true
		}
	case "surface":
		// Surface applicative : les handlers jugent chaque proxy (périmètre) ; la garde ne ferme que les comptes sans accès.
		if isRead(r) {
			return "surface:read", true
		}
		if len(parts) == 2 {
			switch parts[1] {
			case "accept", "relax", "reset":
				return "surface:learn", true
			case "enforce":
				return "surface:enforce", true
			}
		}
	case "vulnscan":
		if len(parts) == 1 {
			return readOrManage(r, "netsec:read", "netsec:analyse")
		}
	case "asn":
		return readOrManage(r, "netsec:read", "netsec:respond")
	case "bans":
		switch {
		case len(parts) >= 2 && parts[1] == "import" && r.Method == http.MethodPost:
			return "bans:import", true
		case isRead(r):
			return "netsec:read", true
		default:
			return "netsec:respond", true
		}
	}
	return "unmapped", true
}

// automationPermission : flux, exécutions, modèles, sourdines (annexe §2.4).
func automationPermission(r *http.Request) (string, bool) {
	parts := pathParts(r, "/api/v1/automation")
	if isRead(r) {
		if len(parts) > 0 {
			switch parts[0] {
			case "flows", "runs", "catalog", "options", "templates", "silences", "stats", "export":
				return "automation:read", true
			}
		}
		return "unmapped", true
	}
	if len(parts) == 0 {
		return "unmapped", true
	}
	switch parts[0] {
	case "flows":
		if len(parts) == 3 && parts[2] == "run" {
			return "automation:run", true
		}
		return "automation:edit", true
	case "runs":
		if len(parts) == 3 {
			switch parts[2] {
			case "approve", "reject":
				return "automation:approve", true
			case "cancel", "replay":
				return "automation:run", true
			}
		}
	case "simulate", "templates", "silences", "import":
		return "automation:edit", true
	}
	return "unmapped", true
}
