// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import "slices"

// Profile est un préréglage de la grille d'un accès (ADR 0022, annexe §3) : un point de départ qui remplit les niveaux
// et les cases à cocher. L'accès créé est ordinaire et modifiable ; un profil se combine avec un périmètre.
type Profile struct {
	ID          string            `json:"id"`
	Label       string            `json:"label"`
	Audience    string            `json:"audience"`
	Levels      map[string]string `json:"levels"`
	Permissions []string          `json:"permissions"`
}

// readsWholePlatform : services de ressource et de plateforme en lecture, sauf ceux qui exposent des comptes, des
// sauvegardes, des réglages ou le journal d'audit.
var notInWholePlatformRead = []string{"accounts", "backups", "settings", "audit", "gdpr", "proxy_sections"}

func wholePlatformRead() map[string]string {
	levels := map[string]string{}
	for _, s := range Services {
		if len(s.Levels) == 0 || slices.Contains(notInWholePlatformRead, s.ID) || s.Levels[0].Class != ClassOrdinary {
			continue
		}
		levels[s.ID] = s.Levels[0].ID
	}
	return levels
}

func merge(base map[string]string, extra map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	for k, v := range extra {
		out[k] = v
	}
	return out
}

// Profiles sont les préréglages proposés à la création d'un accès. Le profil « DPO » n'en fait pas partie : c'est
// l'équipe intégrée, qui porte des capacités et non une grille.
var Profiles = []Profile{
	{ID: "traffic-read", Label: "Lecture du trafic", Audience: "direction, support niveau 1",
		Levels: map[string]string{"proxies": "read", "containers": "read", "surface": "read", "domains": "read", "certs": "read",
			"logs": "read", "dashboard": "read", "alerts": "read"}},
	{ID: "security-read", Label: "Lecture de la sécurité", Audience: "analyste en lecture",
		Levels: map[string]string{"netsec": "read", "engines": "read", "surface": "read", "logs": "read"}},
	{ID: "portal-read", Label: "Lecture du portail", Audience: "responsable conformité",
		Levels: map[string]string{"portal_requests": "read", "portal_sessions": "read", "portal_recordings": "list", "portal_catalog": "read",
			"portal_users": "read", "portal_policies": "read", "portal_audit": "read", "portal_templates": "read"}},
	{ID: "platform-read", Label: "Lecture de toute la plateforme", Audience: "audit interne", Levels: wholePlatformRead()},
	{ID: "operations", Label: "Exploitation", Audience: "équipe d'un environnement ou d'un projet",
		Levels: map[string]string{"proxies": "operate", "containers": "operate", "surface": "learn", "domains": "read", "certs": "read",
			"logs": "read", "dashboard": "read", "alerts": "ack"}},
	{ID: "domain-owner", Label: "Propriétaire de domaine", Audience: "responsable d'un domaine complet",
		Levels: map[string]string{"proxies": "manage", "containers": "operate", "surface": "learn", "domains": "manage", "certs": "manage",
			"logs": "read", "dashboard": "read", "alerts": "rules"}},
	{ID: "soc", Label: "Sécurité (SOC)", Audience: "analystes sécurité",
		Levels: map[string]string{"netsec": "respond", "engines": "simulate", "logs": "read", "dashboard": "read", "surface": "read",
			"proxies": "read", "alerts": "ack"}},
	{ID: "pki", Label: "Certificats et PKI", Audience: "équipe en charge des certificats",
		Levels: map[string]string{"domains": "manage", "certs": "manage", "proxies": "read"}},
	{ID: "infrastructure", Label: "Infrastructure", Audience: "équipe réseau et système",
		Levels: map[string]string{"infra": "classify", "system_logs": "read", "dashboard": "read", "alerts": "ack"}},
	{ID: "on-call", Label: "Astreinte", Audience: "astreinte sans droit de modification",
		Levels: map[string]string{"proxies": "read", "logs": "read", "dashboard": "read", "infra": "read", "netsec": "read", "alerts": "ack"}},
	{ID: "auditor", Label: "Auditeur", Audience: "audit externe",
		Levels: merge(wholePlatformRead(), map[string]string{"audit": "read"})},
	{ID: "portal-support", Label: "Portail : support", Audience: "helpdesk qui approuve les accès temporaires",
		Levels: map[string]string{"portal_requests": "decide", "portal_sessions": "cut", "portal_catalog": "read", "portal_users": "read", "portal_audit": "read"}},
	{ID: "portal-manager", Label: "Portail : gestion", Audience: "responsable du portail",
		Levels: map[string]string{"portal_catalog": "manage", "portal_users": "manage", "portal_policies": "manage", "portal_templates": "manage",
			"portal_requests": "decide", "portal_sessions": "cut", "portal_recordings": "list", "portal_audit": "read"}},
	{ID: "automation-approver", Label: "Approbateur d'automatisation", Audience: "valide les exécutions à risque",
		Levels: map[string]string{"automation": "read"}, Permissions: []string{"automation:approve"}},
	{ID: "empty", Label: "Équipe vide", Audience: "départ de zéro", Levels: map[string]string{}},
}
