// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

// Déclaration des droits de chaque commande de premier niveau (ADR 0022, catalogue : internal/admin/rbac). Une
// commande d'administration appelle l'API de l'Admin : ses permissions sont celles des routes qu'elle appelle, et
// c'est l'Admin qui les applique. TestEveryCommandDeclaresItsRights échoue pour une commande sans déclaration.

type commandKind string

const (
	// commandAPI : appelle l'API de l'Admin ; Permissions liste celles que ses sous-commandes peuvent exiger.
	commandAPI commandKind = "api"
	// commandSelf : agit sur le compte de l'appelant.
	commandSelf commandKind = "self"
	// commandLocal : démarre un composant ou travaille sur des fichiers locaux, sans appeler l'Admin.
	commandLocal commandKind = "local"
)

type commandRights struct {
	Kind        commandKind
	Permissions []string
}

func needs(permissions ...string) commandRights {
	return commandRights{Kind: commandAPI, Permissions: permissions}
}

var commandDeclarations = map[string]commandRights{
	"admin":        {Kind: commandLocal},
	"edge":         {Kind: commandLocal},
	"agent":        {Kind: commandLocal},
	"landing":      {Kind: commandLocal},
	"launcher":     {Kind: commandLocal},
	"update":       {Kind: commandLocal},
	"version":      {Kind: commandLocal},
	"migrate-yaml": {Kind: commandLocal},
	"me":           {Kind: commandSelf},

	"token":         needs("tokens:manage"),
	"backup":        needs("backups:list", "backups:create", "backups:restore"),
	"import":        needs("proxies:import"),
	"alert":         needs("alerts:read", "alerts:ack", "alerts:rules", "alert_channels:read", "alert_channels:manage"),
	"status":        needs("infra:read"),
	"access":        needs("portal_requests:read", "portal_requests:decide", "portal_sessions:read", "portal_sessions:cut", "portal_recordings:list", "portal_recordings:delete", "portal_catalog:read", "portal_catalog:manage", "portal_users:read", "portal_users:manage", "portal_policies:read", "portal_policies:manage", "portal_audit:read", "portal_templates:read", "portal_templates:manage"),
	"nodes":         needs("infra:read", "infra:classify", "architecture:write", "enrol:create"),
	"declared":      needs("infra:read", "architecture:write"),
	"hosts":         needs("infra:read", "enrol:create"),
	"bootstrap":     needs("enrol:create"),
	"automation":    needs("automation:read", "automation:edit", "automation:run", "automation:approve"),
	"security":      needs("netsec:read", "netsec:analyse", "netsec:respond", "bans:import", "engines:read", "engines:simulate", "engines:tune", "surface:read", "surface:learn", "surface:enforce", "domain_watch:read", "proxies:read"),
	"proxy":         needs("proxies:read", "proxies:operate", "proxies:manage", "dashboard:read"),
	"cert":          needs("certs:read", "certs:manage", "certs:deploy"),
	"architecture":  needs("infra:read", "architecture:write"),
	"internal-ca":   needs("pki:read", "pki:write"),
	"user":          needs("accounts:read", "users:write"),
	"audit":         needs("audit:read"),
	"logs":          needs("logs:read", "logs:export", "logs_settings:read", "siem:write", "gdpr:reveal", "gdpr:export", "gdpr:erase"),
	"prism":         needs("dashboard:read", "dashboard:manage"),
	"snippet":       needs("snippets:read", "snippets:write"),
	"ech":           needs("pki:read", "pki:write"),
	"acme":          needs("pki:read", "pki:write"),
	"domain":        needs("domains:read", "domains:manage"),
	"agent-mgmt":    needs("infra:read", "nodes:approve", "discovery:read"),
	"settings":      needs("settings:read", "settings:write"),
	"plugin":        needs("plugins:read", "plugins:write"),
	"auth-provider": needs("auth_providers:read", "auth_providers:write"),
	"teams":         needs("accounts:read", "teams:write"),
	"ip-profile":    needs("ip_profiles:read", "ip_profiles:write"),
	"containers":    needs("containers:read", "containers:operate", "proxies:read"),
}
