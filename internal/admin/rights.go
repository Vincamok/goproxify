// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

// Déclaration des droits de chaque route enregistrée dans server.go (ADR 0022, catalogue : rbac.Services). Ces
// déclarations ne contrôlent rien : le contrôle reste celui des enveloppes (protected, adminOnly…) et des handlers.
// TestEveryRouteDeclaresItsRights échoue pour une route sans déclaration, pour une déclaration orpheline, pour une
// permission absente du catalogue, pour une enveloppe incompatible avec la nature déclarée, et quand le scope de
// jeton que la route exige aujourd'hui (rbac.RequiredScopeForRequest) n'est pas couvert par la permission déclarée.

type routeKind string

const (
	// kindService : route d'un service du catalogue ; Read couvre GET et HEAD, Write les autres méthodes, Delete DELETE
	// quand sa permission diffère de Write.
	kindService routeKind = "service"
	// kindSelf : le compte de l'appelant sur lui-même, sans permission du catalogue.
	kindSelf routeKind = "self"
	// kindPublic : accessible sans authentification (état, documentation, connexion).
	kindPublic routeKind = "public"
	// kindStatic : interface web et ressources statiques.
	kindStatic routeKind = "static"
	// kindSecret : authentifiée par un secret porté par la requête (jeton de ticket, d'appairage, de récupération).
	kindSecret routeKind = "secret"
	// kindGateway : appelée par une passerelle ou un Agent avec son jeton.
	kindGateway routeKind = "gateway"
	// kindMCP : serveur MCP, dont chaque outil déclare sa permission (rbac.ToolPermission).
	kindMCP routeKind = "mcp"
)

type routeRights struct {
	Kind    routeKind
	Service string
	Read    string
	Write   string
	Delete  string
	// Mixed : le sous-arbre mêle plusieurs permissions du service ou d'autres services ; la livraison 2 de l'ADR 0022
	// (descripteurs) le découpe par opération.
	Mixed bool
	Note  string
}

func svc(service, read, write string) routeRights {
	return routeRights{Kind: kindService, Service: service, Read: read, Write: write}
}

func mixed(r routeRights, note string) routeRights {
	r.Mixed, r.Note = true, note
	return r
}

var routeDeclarations = map[string]routeRights{
	// Sans authentification
	"GET /ha/status":                              {Kind: kindPublic, Note: "état d'un membre d'un groupe HA, lu par ses pairs"},
	"GET /openapi.yaml":                           {Kind: kindPublic},
	"GET /api-docs":                               {Kind: kindPublic},
	"GET /api/v1/health":                          {Kind: kindPublic},
	"GET /api/v1/setup/status":                    {Kind: kindPublic},
	"POST /api/v1/setup/init":                     {Kind: kindPublic, Note: "refusée une fois l'installation faite"},
	"POST /api/v1/auth/login":                     {Kind: kindPublic},
	"POST /api/v1/auth/logout":                    {Kind: kindPublic},
	"POST /api/v1/auth/mfa/challenge":             {Kind: kindPublic, Note: "second facteur d'une connexion en cours"},
	"POST /api/v1/auth/mfa/send":                  {Kind: kindPublic, Note: "second facteur d'une connexion en cours"},
	"POST /api/v1/auth/mfa/webauthn/login/begin":  {Kind: kindPublic, Note: "second facteur d'une connexion en cours"},
	"POST /api/v1/auth/mfa/webauthn/login/finish": {Kind: kindPublic, Note: "second facteur d'une connexion en cours"},
	"GET /map/basemap.pmtiles":                    {Kind: kindStatic},
	"/":                                           {Kind: kindStatic},

	// Secret porté par la requête
	"GET /i/{token}":                {Kind: kindSecret, Note: "ticket d'enrôlement"},
	"GET /api/v1/bootstrap/{token}": {Kind: kindSecret, Note: "ticket d'enrôlement"},
	"GET /api/v1/join/{token}":      {Kind: kindSecret, Note: "ticket de jonction"},
	"POST /internal/v1/pair":        {Kind: kindSecret, Note: "secret d'appairage"},
	"GET /internal/v1/pair/status":  {Kind: kindSecret, Note: "secret d'appairage"},
	"/api/v1/cert-bundle":           {Kind: kindSecret, Note: "jeton de récupération d'un certificat"},

	// Passerelles et Agents
	"POST /internal/v1/edges/register": {Kind: kindGateway},
	"GET /internal/v1/routes":          {Kind: kindGateway},
	"GET /internal/v1/nodes/metrics":   {Kind: kindGateway},
	"/internal/v1/logs":                {Kind: kindGateway},
	"/internal/v1/security/bans":       {Kind: kindGateway},
	"/internal/v1/security/threats":    {Kind: kindGateway},
	"/internal/v1/security/cves":       {Kind: kindGateway},
	"/internal/v1/heartbeat":           {Kind: kindGateway},
	"/internal/v1/events":              {Kind: kindGateway},

	// MCP
	"/mcp":  {Kind: kindMCP},
	"/mcp/": {Kind: kindMCP},

	// Le compte de l'appelant
	"/api/v1/me":          {Kind: kindSelf},
	"/api/v1/me/":         {Kind: kindSelf},
	"/api/v1/me/tokens":   {Kind: kindSelf, Note: "jetons de l'appelant, scopes bornés par son rôle"},
	"/api/v1/me/tokens/":  {Kind: kindSelf, Note: "jetons de l'appelant, scopes bornés par son rôle"},
	"GET /api/v1/auth/me": {Kind: kindSelf},
	"/api/v1/auth/mfa":    {Kind: kindSelf, Note: "second facteur de l'appelant"},
	"/api/v1/auth/mfa/":   {Kind: kindSelf, Note: "second facteur de l'appelant"},

	// Trafic
	"/api/v1/proxies":                mixed(routeRights{Kind: kindService, Service: "proxies", Read: "proxies:read", Write: "proxies:operate", Delete: "proxies:manage"}, "sections, surface, étiquettes, purge du cache"),
	"/api/v1/proxies/":               mixed(routeRights{Kind: kindService, Service: "proxies", Read: "proxies:read", Write: "proxies:operate", Delete: "proxies:manage"}, "sections, surface, étiquettes, purge du cache"),
	"/api/v1/discovered-containers":  svc("containers", "containers:read", "containers:operate"),
	"/api/v1/discovered-containers/": svc("containers", "containers:read", "containers:operate"),
	"/api/v1/domains":                svc("domains", "domains:read", "domains:manage"),
	"/api/v1/domains/":               svc("domains", "domains:read", "domains:manage"),
	"/api/v1/certs":                  mixed(svc("certs", "certs:read", "certs:manage"), "cibles de déploiement et jetons de récupération"),
	"/api/v1/certs/":                 mixed(svc("certs", "certs:read", "certs:manage"), "cibles de déploiement et jetons de récupération"),
	"/api/v1/cert-deploy-types":      svc("certs", "certs:read", "certs:manage"),
	"/api/v1/import":                 mixed(svc("proxies", "audit:read", "proxies:import"), "lecture d'un état d'import : scope audit:read aujourd'hui"),
	"/api/v1/import/":                mixed(svc("proxies", "audit:read", "proxies:import"), "lecture d'un état d'import : scope audit:read aujourd'hui"),

	// Observabilité
	"/api/v1/node-events":         svc("infra", "infra:read", "infra:classify"),
	"/api/v1/backends/health":     svc("infra", "infra:read", "infra:classify"),
	"/api/v1/metrics/proxies":     svc("dashboard", "dashboard:read", "dashboard:manage"),
	"/api/v1/metrics/summary":     svc("dashboard", "dashboard:read", "dashboard:manage"),
	"/api/v1/prism/":              svc("dashboard", "dashboard:read", "dashboard:manage"),
	"/api/v1/audit":               svc("audit", "audit:read", "audit:read"),
	"/api/v1/audit/":              svc("audit", "audit:read", "audit:read"),
	"/api/v1/alert-channel-types": svc("alert_channels", "alert_channels:read", "alert_channels:manage"),
	"/api/v1/alert-channels":      mixed(svc("alert_channels", "alert_channels:read", "alert_channels:manage"), "envoi d'un message de test"),
	"/api/v1/alert-channels/":     mixed(svc("alert_channels", "alert_channels:read", "alert_channels:manage"), "envoi d'un message de test"),
	"/api/v1/alert-events":        svc("alerts", "alerts:read", "alerts:ack"),
	"/api/v1/alert-events/":       svc("alerts", "alerts:read", "alerts:ack"),
	"/api/v1/alert-rules":         svc("alerts", "alerts:read", "alerts:rules"),
	"/api/v1/alert-rules/":        svc("alerts", "alerts:read", "alerts:rules"),
	"/api/v1/logs":                mixed(svc("logs", "logs:read", "logs:export"), "logs système et conteneurs, réglages des logs"),
	"/api/v1/logs/":               mixed(svc("logs", "logs:read", "logs:export"), "logs système et conteneurs, réglages des logs"),
	"/api/v1/logs/reveal-ip":      svc("gdpr", "gdpr:reveal", "gdpr:reveal"),
	"/api/v1/logs/subject-export": svc("gdpr", "gdpr:export", "gdpr:export"),
	"/api/v1/logs/by-ip/":         svc("gdpr", "gdpr:erase", "gdpr:erase"),
	"/api/v1/logs/by-user/":       svc("gdpr", "gdpr:erase", "gdpr:erase"),
	"/api/v1/logs/siem":           svc("logs_settings", "logs_settings:read", "siem:write"),
	"/api/v1/logs/siem/status":    svc("logs_settings", "logs_settings:read", "siem:write"),

	// Sécurité
	"/api/v1/security/engine-types": svc("engines", "engines:read", "engines:tune"),
	"/api/v1/security":              mixed(svc("netsec", "netsec:read", "netsec:respond"), "moteurs, surface, domaines surveillés, liste blanche"),
	"/api/v1/security/":             mixed(svc("netsec", "netsec:read", "netsec:respond"), "moteurs, surface, domaines surveillés, liste blanche"),
	"GET /api/v1/edges/waf-status":  svc("engines", "engines:read", "engines:tune"),
	"/api/v1/detector-types":        svc("snippets", "snippets:read", "snippets:write"),
	"/api/v1/snippets":              svc("snippets", "snippets:read", "snippets:write"),
	"/api/v1/snippets/":             svc("snippets", "snippets:read", "snippets:write"),
	"/api/v1/ip-profiles":           svc("ip_profiles", "ip_profiles:read", "ip_profiles:write"),
	"/api/v1/ip-profiles/":          svc("ip_profiles", "ip_profiles:read", "ip_profiles:write"),
	"/api/v1/auth-provider-types":   svc("auth_providers", "auth_providers:read", "auth_providers:write"),
	"/api/v1/auth-providers":        svc("auth_providers", "auth_providers:read", "auth_providers:write"),
	"/api/v1/auth-providers/":       svc("auth_providers", "auth_providers:read", "auth_providers:write"),
	"/api/v1/error-page-templates":  svc("error_pages", "error_pages:read", "error_pages:write"),
	"/api/v1/error-page-templates/": svc("error_pages", "error_pages:read", "error_pages:write"),

	// Plateforme
	"/api/v1/nodes":                         mixed(svc("infra", "infra:read", "infra:classify"), "approbation, mise à jour, configuration, tunnel, suppression, groupes HA"),
	"/api/v1/nodes/":                        mixed(svc("infra", "infra:read", "infra:classify"), "approbation, mise à jour, configuration, tunnel, suppression, groupes HA"),
	"/api/v1/agents":                        mixed(svc("infra", "infra:read", "nodes:approve"), "Agents : approbation, révocation, découverte"),
	"/api/v1/agents/":                       mixed(svc("infra", "infra:read", "nodes:approve"), "Agents : approbation, révocation, découverte"),
	"/api/v1/declared-nodes":                svc("infra", "infra:read", "architecture:write"),
	"/api/v1/declared-nodes/":               svc("infra", "infra:read", "architecture:write"),
	"/api/v1/architecture":                  svc("infra", "infra:read", "architecture:write"),
	"GET /api/v1/architecture/groups":       svc("infra", "infra:read", "architecture:write"),
	"/api/v1/architecture/":                 svc("infra", "infra:read", "architecture:write"),
	"POST /api/v1/bootstrap-tickets":        {Kind: kindService, Service: "infra", Write: "enrol:create"},
	"GET /api/v1/hosts":                     {Kind: kindService, Service: "infra", Read: "infra:read"},
	"POST /api/v1/hosts/{name}/join-ticket": {Kind: kindService, Service: "infra", Write: "enrol:create"},
	"GET /api/v1/pairing-secret":            {Kind: kindService, Service: "infra", Read: "enrol:create"},
	"/api/v1/tokens":                        svc("gateway_scope", "tokens:manage", "tokens:manage"),
	"/api/v1/tokens/":                       svc("gateway_scope", "tokens:manage", "tokens:manage"),
	"/api/v1/discovery-sources":             svc("discovery", "discovery:read", "discovery:write"),
	"/api/v1/automation/":                   mixed(svc("automation", "automation:read", "automation:edit"), "exécution et décision d'un flux"),

	// Portail Access
	"/api/v1/portal":                 mixed(svc("portal_templates", "portal_templates:read", "portal_templates:manage"), "huit sous-services du portail"),
	"/api/v1/portal/":                mixed(svc("portal_templates", "portal_templates:read", "portal_templates:manage"), "huit sous-services du portail"),
	"/api/v1/portal-page-templates":  svc("portal_templates", "portal_templates:read", "portal_templates:manage"),
	"/api/v1/portal-page-templates/": svc("portal_templates", "portal_templates:read", "portal_templates:manage"),

	// Administration
	"/api/v1/backups":             mixed(svc("backups", "backups:list", "backups:create"), "restauration"),
	"/api/v1/backups/":            mixed(svc("backups", "backups:list", "backups:create"), "restauration"),
	"/api/v1/internal-ca":         svc("pki", "pki:read", "pki:write"),
	"/api/v1/internal-ca/":        svc("pki", "pki:read", "pki:write"),
	"/api/v1/ech":                 svc("pki", "pki:read", "pki:write"),
	"/api/v1/ech/":                svc("pki", "pki:read", "pki:write"),
	"/api/v1/acme/provider-types": svc("pki", "pki:read", "pki:write"),
	"/api/v1/acme/providers":      svc("pki", "pki:read", "pki:write"),
	"/api/v1/acme/providers/":     svc("pki", "pki:read", "pki:write"),
	"/api/v1/settings/acme":       svc("pki", "pki:read", "pki:write"),
	"/api/v1/plugins":             svc("plugins", "plugins:read", "plugins:write"),
	"/api/v1/plugins/":            svc("plugins", "plugins:read", "plugins:write"),
	"/api/v1/plugin-keys":         svc("plugins", "plugins:read", "plugins:write"),
	"/api/v1/plugin-keys/":        svc("plugins", "plugins:read", "plugins:write"),
	"/api/v1/plugin-repos":        svc("plugins", "plugins:read", "plugins:write"),
	"/api/v1/plugin-repos/":       svc("plugins", "plugins:read", "plugins:write"),
	"/api/v1/users":               svc("accounts", "accounts:read", "users:write"),
	"/api/v1/users/":              svc("accounts", "accounts:read", "users:write"),
	"/api/v1/teams":               svc("accounts", "accounts:read", "teams:write"),
	"/api/v1/teams/":              svc("accounts", "accounts:read", "teams:write"),
	"/api/v1/mcp-access/":         svc("accounts", "accounts:read", "users:write"),
	"/api/v1/settings/mfa/":       svc("settings", "settings:read", "settings:write"),
	"/api/v1/settings/smtp":       svc("settings", "settings:read", "settings:write"),
	"/api/v1/settings/smtp/":      svc("settings", "settings:read", "settings:write"),
}
