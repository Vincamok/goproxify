// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

// Catalogue v1 des scopes ressource (API + MCP).
const (
	ScopeProxiesRead   = "proxies:read"
	ScopeProxiesWrite  = "proxies:write"
	ScopeProxiesDelete = "proxies:delete"
	ScopeNodesRead     = "nodes:read"
	ScopeNodesWrite    = "nodes:write"
	ScopeAlertsRead    = "alerts:read"
	ScopeAlertsWrite   = "alerts:write"
	ScopeMetricsRead   = "metrics:read"
	ScopeBackupsRead   = "backups:read"
	ScopeUsersRead     = "users:read"
	ScopeSnippetsRead  = "snippets:read"
	ScopeSnippetsWrite = "snippets:write"
	ScopeDomainsRead   = "domains:read"
	ScopeDomainsWrite  = "domains:write"
	ScopeCertsRead     = "certs:read"
	ScopeCertsWrite    = "certs:write"
	ScopeLogsRead      = "logs:read"
	ScopeLogsWrite     = "logs:write"
	ScopeTeamsRead     = "teams:read"
	ScopeAuditRead     = "audit:read"
	ScopeSecurityWrite = "security:write"
	ScopeImportWrite   = "import:write"
	ScopePairingRead   = "pairing:read"
	ScopePortalRead    = "portal:read"
	ScopePortalWrite   = "portal:write"
	ScopeGDPRReveal    = "gdpr:reveal"
)

// AllPATScopes liste tous les scopes connus (ordre stable pour l'UI).
var AllPATScopes = []string{
	ScopeProxiesRead, ScopeProxiesWrite, ScopeProxiesDelete,
	ScopeNodesRead, ScopeNodesWrite, ScopeAlertsRead, ScopeAlertsWrite, ScopeMetricsRead, ScopeBackupsRead,
	ScopeUsersRead, ScopeSnippetsRead, ScopeSnippetsWrite,
	ScopeDomainsRead, ScopeDomainsWrite, ScopeCertsRead, ScopeCertsWrite,
	ScopeLogsRead, ScopeLogsWrite, ScopeTeamsRead, ScopeAuditRead,
	ScopeSecurityWrite, ScopeImportWrite, ScopePairingRead,
	ScopePortalRead, ScopePortalWrite,
	ScopeGDPRReveal,
}

// ScopeMeta décrit un scope pour l'UI / API.
type ScopeMeta struct {
	ID          string `json:"id"`
	Description string `json:"description"`
}

// ScopeCatalog retourne les métadonnées de tous les scopes.
func ScopeCatalog() []ScopeMeta {
	desc := map[string]string{
		ScopeProxiesRead:   "Lister et lire les proxies",
		ScopeProxiesWrite:  "Créer et modifier les proxies",
		ScopeProxiesDelete: "Supprimer des proxies",
		ScopeNodesRead:     "Lister les nœuds / Passerelles",
		ScopeNodesWrite:    "Approuver / révoquer Agents et muter les nœuds",
		ScopeAlertsRead:    "Lister les alertes, canaux, règles et événements d'alerte",
		ScopeAlertsWrite:   "Créer / supprimer canaux et règles d'alerte, acquitter les événements",
		ScopeMetricsRead:   "Lire les métriques",
		ScopeBackupsRead:   "Lister les sauvegardes",
		ScopeUsersRead:     "Lister les utilisateurs",
		ScopeSnippetsRead:  "Lister les snippets",
		ScopeSnippetsWrite: "Créer et modifier les snippets",
		ScopeDomainsRead:   "Lister les domaines",
		ScopeDomainsWrite:  "Créer, modifier, supprimer et renouveler les domaines",
		ScopeCertsRead:     "Lister les certificats, cibles de déploiement et CA internes",
		ScopeCertsWrite:    "Obtenir, importer, supprimer et déployer des certificats ; gérer la CA interne",
		ScopeLogsRead:      "Lire les logs",
		ScopeLogsWrite:     "Modifier les réglages des logs (rétention, protection des IP) et effacer des logs (RGPD Art. 17)",
		ScopeTeamsRead:     "Lister les équipes",
		ScopeAuditRead:     "Lire le journal d'audit, la sécurité (bans, menaces, CVE, profils IP, fournisseurs d'auth) et l'automatisation (règles, tâches planifiées, playbooks)",
		ScopeSecurityWrite: "Muter la sécurité (bans, profils IP, fournisseurs d'auth) et piloter l'automatisation (règles, tâches planifiées, playbooks)",
		ScopeImportWrite:   "Importer des configurations",
		ScopePairingRead:   "Lire le secret d'appairage",
		ScopePortalRead:    "Lire GoProxify Access (config, catalogue, users, templates, audit)",
		ScopePortalWrite:   "Gérer GoProxify Access (config, catalogue, invitations, templates, push)",
		ScopeGDPRReveal:    "Révéler l'IP réelle d'une entrée de log pseudonymisée (RGPD — DPO/juriste/RSSI uniquement)",
	}
	out := make([]ScopeMeta, 0, len(AllPATScopes))
	for _, id := range AllPATScopes {
		out = append(out, ScopeMeta{ID: id, Description: desc[id]})
	}
	return out
}

// mcpTools liste tous les outils MCP, dans un ordre stable, pour dériver
// la carte scope → outils de /mcp-access sans dupliquer ToolRequiredScope.
// Doit contenir exactement les outils du serveur MCP (vérifié par un test de internal/admin/mcp).
var mcpTools = []string{
	"list_proxies", "get_proxy", "create_proxy", "update_proxy", "set_proxy_enabled", "delete_proxy", "purge_proxy_cache",
	"list_nodes", "list_agents", "list_declared_nodes", "get_topology_live", "get_architecture",
	"approve_agent", "revoke_agent", "create_declared_node", "delete_declared_node",
	"create_bootstrap_ticket", "accept_node", "reject_node",
	"list_alerts", "list_alert_events", "list_alert_channels", "list_alert_rules",
	"create_alert_channel", "delete_alert_channel", "create_alert_rule", "delete_alert_rule", "ack_alert_event",
	"get_metrics", "get_proxy_metrics", "list_backups", "list_users",
	"list_snippets", "create_snippet", "delete_snippet",
	"list_domains", "create_domain", "renew_domain", "rotate_cert",
	"list_certs", "get_cert_status", "list_cert_deploy_targets", "list_internal_cas", "list_internal_certs", "get_ech_status",
	"obtain_cert", "import_cert", "trigger_cert_deploy", "create_internal_ca", "issue_internal_cert", "revoke_internal_cert",
	"list_logs", "simulate_sentinel_config", "trace_ip", "preview_security_ban", "preview_asn_ban", "get_prism_anomalies", "get_prism_geo", "get_prism_tls_fingerprints", "get_prism_slo", "list_teams",
	"get_audit_log", "get_security_overview", "list_security_bans", "lookup_asn", "list_security_threats", "list_security_cves",
	"list_ip_profiles", "list_auth_providers",
	"list_rules", "list_rule_history", "list_pending_actions", "list_rule_versions", "list_silences", "export_automation",
	"list_scheduled_tasks", "list_scheduled_task_runs", "list_playbooks", "list_playbook_runs", "get_playbook_run",
	"create_security_ban", "delete_security_ban", "ban_ip", "unban_ip", "list_ban_whitelist", "add_ban_whitelist", "remove_ban_whitelist", "import_security_bans", "ban_asn", "unban_asn",
	"create_ip_profile", "delete_ip_profile", "create_auth_provider", "delete_auth_provider",
	"run_rule", "replay_rule_history", "approve_pending_action", "reject_pending_action", "restore_rule_version",
	"create_silence", "import_automation",
	"create_scheduled_task", "update_scheduled_task", "delete_scheduled_task", "run_scheduled_task",
	"create_playbook", "update_playbook", "delete_playbook", "run_playbook_now", "approve_playbook_run", "reject_playbook_run",
	"get_portal_config", "list_portal_destinations", "preview_portal_destinations", "list_portal_destination_groups",
	"list_portal_users", "list_portal_groups", "list_portal_audit", "list_portal_sessions", "terminate_portal_session", "list_portal_access_requests", "decide_portal_access_request", "get_portal_policy", "set_portal_policy", "list_portal_recordings", "delete_portal_recording", "list_portal_templates", "get_portal_template",
	"update_portal_config", "push_portal",
	"create_portal_destination", "update_portal_destination", "delete_portal_destination",
	"create_portal_destination_group", "update_portal_destination_group", "delete_portal_destination_group",
	"invite_portal_user", "create_portal_group", "update_portal_group", "delete_portal_group", "update_portal_user", "delete_portal_user", "resend_portal_invite",
	"upsert_portal_template", "delete_portal_template", "push_portal_templates",
}

// ToolsForScope retourne, pour l'UI, la liste des outils MCP couverts par un scope donné.
func ToolsForScope(scope string) []string {
	var out []string
	for _, tool := range mcpTools {
		if ToolRequiredScope(tool) == scope {
			out = append(out, tool)
		}
	}
	return out
}

// IsKnownScope indique si le scope fait partie du catalogue v1.
func IsKnownScope(scope string) bool {
	for _, s := range AllPATScopes {
		if s == scope {
			return true
		}
	}
	return false
}

// AvailableScopesForUser retourne les scopes que le compte peut actuellement déléguer / exercer.
func AvailableScopesForUser(ctx context.Context, db *sql.DB, userID string) []string {
	role := UserRole(ctx, db, userID)
	if role == "" {
		return nil
	}
	var out []string
	add := func(scopes ...string) {
		for _, s := range scopes {
			out = append(out, s)
		}
	}
	// Lecture de base pour tout compte authentifié
	add(ScopeProxiesRead, ScopeNodesRead, ScopeAlertsRead, ScopeMetricsRead,
		ScopeBackupsRead, ScopeSnippetsRead, ScopeDomainsRead, ScopeCertsRead,
		ScopeLogsRead, ScopeAuditRead)

	switch {
	case IsSuperAdminRole(role):
		add(ScopeProxiesWrite, ScopeProxiesDelete, ScopeSnippetsWrite, ScopeUsersRead, ScopeTeamsRead,
			ScopeNodesWrite, ScopeAlertsWrite, ScopeDomainsWrite, ScopeCertsWrite, ScopeLogsWrite,
			ScopeSecurityWrite, ScopeImportWrite, ScopePairingRead,
			ScopePortalRead, ScopePortalWrite)
	case IsAdminRole(role):
		add(ScopeProxiesWrite, ScopeProxiesDelete, ScopeSnippetsWrite, ScopeUsersRead, ScopeTeamsRead,
			ScopeNodesWrite, ScopeAlertsWrite, ScopeDomainsWrite, ScopeCertsWrite, ScopeLogsWrite,
			ScopeSecurityWrite, ScopeImportWrite, ScopePairingRead,
			ScopePortalRead, ScopePortalWrite)
	default:
		// user, dpo (et legacy operator/viewer normalisés) : write PAT si grant write effectif
		if UserHasWriteGrant(ctx, db, userID) {
			add(ScopeProxiesWrite, ScopeSnippetsWrite)
		}
	}
	// Superadmin, rôle dpo, ou permission accordée en propre / via une équipe.
	if HasPermission(ctx, db, userID, PermGDPRReveal) {
		add(ScopeGDPRReveal)
	}
	return out
}

// UserCanHoldScope indique si le compte possède actuellement ce droit.
func UserCanHoldScope(ctx context.Context, db *sql.DB, userID, scope string) bool {
	for _, s := range AvailableScopesForUser(ctx, db, userID) {
		if s == scope {
			return true
		}
	}
	return false
}

// EffectiveHasScope applique scopes PAT ∩ droits courants (ou droits seuls pour JWT).
func EffectiveHasScope(ctx context.Context, db *sql.DB, scope string) bool {
	userID := auth.UserIDFromContext(ctx)
	if userID == "" || !UserCanHoldScope(ctx, db, userID, scope) {
		return false
	}
	if !auth.IsPATAuth(ctx) {
		return true
	}
	for _, s := range auth.PATScopesFromContext(ctx) {
		if s == scope {
			return true
		}
	}
	return false
}

// ToolRequiredScope mappe un outil MCP vers le scope requis, aligné sur
// RequiredScopeForRequest pour la route REST équivalente. "" = outil sans scope :
// le serveur MCP le refuse.
func ToolRequiredScope(tool string) string {
	switch tool {
	case "list_proxies", "get_proxy":
		return ScopeProxiesRead
	case "create_proxy", "update_proxy", "set_proxy_enabled", "purge_proxy_cache":
		return ScopeProxiesWrite
	case "delete_proxy":
		return ScopeProxiesDelete
	case "list_nodes", "list_agents", "list_declared_nodes", "get_topology_live", "get_architecture":
		return ScopeNodesRead
	case "approve_agent", "revoke_agent",
		"create_declared_node", "delete_declared_node",
		"create_bootstrap_ticket", "accept_node", "reject_node":
		return ScopeNodesWrite
	case "list_alerts", "list_alert_events", "list_alert_channels", "list_alert_rules":
		return ScopeAlertsRead
	case "create_alert_channel", "delete_alert_channel", "create_alert_rule", "delete_alert_rule", "ack_alert_event":
		return ScopeAlertsWrite
	case "get_metrics", "get_proxy_metrics":
		return ScopeMetricsRead
	case "list_backups":
		return ScopeBackupsRead
	case "list_users":
		return ScopeUsersRead
	case "list_snippets":
		return ScopeSnippetsRead
	case "create_snippet", "delete_snippet":
		return ScopeSnippetsWrite
	case "list_domains":
		return ScopeDomainsRead
	case "create_domain", "renew_domain", "rotate_cert":
		return ScopeDomainsWrite
	case "list_certs", "get_cert_status", "list_cert_deploy_targets", "list_internal_cas", "list_internal_certs", "get_ech_status":
		return ScopeCertsRead
	case "obtain_cert", "import_cert", "trigger_cert_deploy",
		"create_internal_ca", "issue_internal_cert", "revoke_internal_cert":
		return ScopeCertsWrite
	case "list_logs", "simulate_sentinel_config", "trace_ip", "preview_security_ban", "preview_asn_ban", "get_prism_anomalies", "get_prism_geo", "get_prism_tls_fingerprints", "get_prism_slo":
		return ScopeLogsRead
	case "list_teams":
		return ScopeTeamsRead
	case "get_audit_log",
		"get_security_overview", "list_security_bans", "lookup_asn", "list_ban_whitelist",
		"list_security_threats", "list_security_cves",
		"list_ip_profiles", "list_auth_providers",
		"list_rules", "list_rule_history", "list_pending_actions", "list_rule_versions",
		"list_silences", "export_automation",
		"list_scheduled_tasks", "list_scheduled_task_runs",
		"list_playbooks", "list_playbook_runs", "get_playbook_run":
		return ScopeAuditRead
	case "create_security_ban", "delete_security_ban", "ban_ip", "unban_ip", "add_ban_whitelist", "remove_ban_whitelist", "import_security_bans", "ban_asn", "unban_asn",
		"create_ip_profile", "delete_ip_profile", "create_auth_provider", "delete_auth_provider",
		"run_rule", "replay_rule_history", "approve_pending_action", "reject_pending_action",
		"restore_rule_version", "create_silence", "import_automation",
		"create_scheduled_task", "update_scheduled_task", "delete_scheduled_task", "run_scheduled_task",
		"create_playbook", "update_playbook", "delete_playbook", "run_playbook_now",
		"approve_playbook_run", "reject_playbook_run":
		return ScopeSecurityWrite
	case "get_portal_config", "list_portal_destinations", "preview_portal_destinations", "list_portal_destination_groups",
		"list_portal_users", "list_portal_groups", "list_portal_audit", "list_portal_sessions", "list_portal_access_requests", "get_portal_policy", "list_portal_recordings", "list_portal_templates", "get_portal_template":
		return ScopePortalRead
	case "update_portal_config", "push_portal",
		"create_portal_destination", "update_portal_destination", "delete_portal_destination",
		"create_portal_destination_group", "update_portal_destination_group", "delete_portal_destination_group",
		"invite_portal_user", "create_portal_group", "update_portal_group", "delete_portal_group", "update_portal_user", "delete_portal_user", "resend_portal_invite",
		"terminate_portal_session", "decide_portal_access_request", "set_portal_policy", "delete_portal_recording", "upsert_portal_template", "delete_portal_template", "push_portal_templates":
		return ScopePortalWrite
	default:
		return ""
	}
}

// ToolRequiresAdmin indique si la route REST équivalente de l'outil est adminOnly.
// /mcp n'est monté qu'avec RequirePAT : sans ce contrôle, un compte user tenant un
// scope de lecture commun (audit:read, certs:read…) passerait là où REST le refuse.
func ToolRequiresAdmin(tool string) bool {
	switch ToolRequiredScope(tool) {
	case ScopePortalRead, ScopePortalWrite:
		return true
	}
	switch tool {
	case "list_agents", "approve_agent", "revoke_agent",
		"get_architecture",
		"list_backups", "list_users", "list_teams",
		"get_security_overview", "list_security_bans", "lookup_asn", "list_security_threats", "list_security_cves",
		"create_security_ban", "delete_security_ban", "ban_ip", "unban_ip", "simulate_sentinel_config", "trace_ip", "preview_security_ban", "preview_asn_ban", "list_ban_whitelist", "add_ban_whitelist", "remove_ban_whitelist", "import_security_bans", "ban_asn", "unban_asn",
		"list_auth_providers", "create_auth_provider", "delete_auth_provider",
		"list_internal_cas", "list_internal_certs", "get_ech_status", "create_internal_ca", "issue_internal_cert", "revoke_internal_cert",
		"list_rules", "run_rule", "list_rule_history", "replay_rule_history",
		"list_pending_actions", "approve_pending_action", "reject_pending_action",
		"list_rule_versions", "restore_rule_version",
		"list_silences", "create_silence", "export_automation", "import_automation",
		"list_scheduled_tasks", "create_scheduled_task", "update_scheduled_task", "delete_scheduled_task",
		"run_scheduled_task", "list_scheduled_task_runs",
		"list_playbooks", "create_playbook", "update_playbook", "delete_playbook", "run_playbook_now",
		"list_playbook_runs", "get_playbook_run", "approve_playbook_run", "reject_playbook_run":
		return true
	}
	return false
}

// RequiredScopeForRequest déduit le scope API pour une requête REST (PAT uniquement).
// Retourne "" si aucune contrainte de scope PAT (ex. /me, MFA).
func RequiredScopeForRequest(r *http.Request) string {
	path := r.URL.Path
	method := r.Method

	// Gestion des PAT self-service : JWT seulement (vérifié ailleurs) — pas de scope.
	if strings.HasPrefix(path, "/api/v1/me") {
		return ""
	}
	if strings.HasPrefix(path, "/api/v1/auth/") {
		return ""
	}
	if strings.HasPrefix(path, "/api/v1/settings/mfa") {
		return ""
	}
	if path == "/api/v1/pairing-secret" {
		return ScopePairingRead
	}

	switch {
	case strings.HasPrefix(path, "/api/v1/proxies"):
		switch method {
		case http.MethodGet:
			return ScopeProxiesRead
		case http.MethodDelete:
			return ScopeProxiesDelete
		default:
			return ScopeProxiesWrite
		}
	case strings.HasPrefix(path, "/api/v1/nodes"),
		strings.HasPrefix(path, "/api/v1/declared-nodes"),
		strings.HasPrefix(path, "/api/v1/bootstrap-tickets"),
		strings.HasPrefix(path, "/api/v1/node-events"),
		strings.HasPrefix(path, "/api/v1/discovered-containers"),
		strings.HasPrefix(path, "/api/v1/backends/health"),
		strings.HasPrefix(path, "/api/v1/agents"):
		if method == http.MethodGet {
			return ScopeNodesRead
		}
		return ScopeNodesWrite
	case strings.HasPrefix(path, "/api/v1/alert"):
		if method == http.MethodGet {
			return ScopeAlertsRead
		}
		return ScopeAlertsWrite
	case strings.HasPrefix(path, "/api/v1/prism"),
		strings.HasPrefix(path, "/api/v1/metrics/proxies"),
		strings.HasPrefix(path, "/api/v1/metrics/summary"):
		return ScopeMetricsRead
	case strings.HasPrefix(path, "/api/v1/backups"):
		return ScopeBackupsRead
	case strings.HasPrefix(path, "/api/v1/users"):
		return ScopeUsersRead
	case strings.HasPrefix(path, "/api/v1/snippets"):
		if method == http.MethodGet {
			return ScopeSnippetsRead
		}
		return ScopeSnippetsWrite
	case strings.HasPrefix(path, "/api/v1/domains"):
		if method == http.MethodGet {
			return ScopeDomainsRead
		}
		return ScopeDomainsWrite
	case strings.HasPrefix(path, "/api/v1/certs"),
		strings.HasPrefix(path, "/api/v1/internal-ca"),
		strings.HasPrefix(path, "/api/v1/ech"):
		if method == http.MethodGet {
			return ScopeCertsRead
		}
		return ScopeCertsWrite
	case strings.HasPrefix(path, "/api/v1/logs/reveal-ip"):
		return ScopeGDPRReveal
	case strings.HasPrefix(path, "/api/v1/logs"):
		if method == http.MethodGet {
		return ScopeLogsRead
		}
		return ScopeLogsWrite
	case strings.HasPrefix(path, "/api/v1/teams"):
		return ScopeTeamsRead
	case strings.HasPrefix(path, "/api/v1/audit"):
		return ScopeAuditRead
	case strings.HasPrefix(path, "/api/v1/tokens"):
		// Tokens d'appairage : réservé admin ; un PAT ne doit pas les gérer sans users-like droit.
		return ScopeUsersRead
	case strings.HasPrefix(path, "/api/v1/security"),
		strings.HasPrefix(path, "/api/v1/ip-profiles"),
		strings.HasPrefix(path, "/api/v1/auth-providers"),
		strings.HasPrefix(path, "/api/v1/rules-engine"),
		strings.HasPrefix(path, "/api/v1/scheduled-tasks"),
		strings.HasPrefix(path, "/api/v1/playbooks"):
		if method == http.MethodGet {
			return ScopeAuditRead
		}
		return ScopeSecurityWrite
	case strings.HasPrefix(path, "/api/v1/import"):
		if method == http.MethodGet {
			return ScopeAuditRead
		}
		return ScopeImportWrite
	case strings.HasPrefix(path, "/api/v1/portal/recordings/"),
		strings.HasPrefix(path, "/api/v1/portal/sessions/") && strings.HasSuffix(path, "/watch"):
		// Contenu d'un terminal (rejeu, observation en direct) : plus sensible qu'une simple lecture.
		return ScopePortalWrite
	case strings.HasPrefix(path, "/api/v1/portal"),
		strings.HasPrefix(path, "/api/v1/portal-page-templates"):
		if method == http.MethodGet {
			return ScopePortalRead
		}
		return ScopePortalWrite
	default:
		return ""
	}
}

// EnforcePATScope refuse les requêtes PAT sans le scope effectif requis.
func EnforcePATScope(db *sql.DB) func(http.Handler) http.Handler {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !auth.IsPATAuth(r.Context()) {
				next.ServeHTTP(w, r)
				return
			}
			required := RequiredScopeForRequest(r)
			if required == "" {
				next.ServeHTTP(w, r)
				return
			}
			if !EffectiveHasScope(r.Context(), db, required) {
				http.Error(w, "scope insuffisant: "+required, http.StatusForbidden)
				return
			}
			next.ServeHTTP(w, r)
		})
	}
}
