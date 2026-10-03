// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/security"
)

func banPreviewTools() []map[string]any {
	return []map[string]any{{
		"name": "preview_security_ban",
		"description": "Aperçu de l'impact d'un ban IP ou CIDR avant de le créer, sans rien modifier : trafic récent de la cible " +
			"(requêtes, dont celles qui ont réussi et seraient coupées, adresses distinctes, pays), bans actifs et profils IP qui la recoupent, " +
			"et avertissements (plage privée, profil allow, déjà couverte, auto-verrouillage). La cible est normalisée comme à la création " +
			"(203.0.113.7/24 devient 203.0.113.0/24) ; une plage plus large que /16 (IPv4) ou /32 (IPv6) est refusée.",
		"inputSchema": schema(
			req("ip", "string", "IP ou CIDR (203.0.113.7, 198.51.100.0/24, 2001:db8::/32)"),
			opt("hours", "number", "Période de trafic analysée en heures (défaut 24, max 168)"),
		),
	}}
}

func init() { tools = append(tools, banPreviewTools()...) }

func (h *Handler) toolPreviewSecurityBan(r *http.Request, args map[string]any) (any, error) {
	raw, _ := args["ip"].(string)
	t, err := security.ParseBanTarget(raw)
	if err != nil {
		return nil, err
	}
	hours := 24
	if v, ok := args["hours"].(float64); ok && v > 0 {
		hours = int(v)
	}
	if hours > 168 {
		hours = 168
	}
	return api.BanPreview(r.Context(), h.DB, t, hours, api.RequesterIP(r))
}

// banTarget valide la cible d'un ban demandé par un outil MCP : IP ou CIDR normalisé, refus d'une
// plage trop large, qui couperait l'appelant ou qui est entièrement en liste blanche.
func (h *Handler) banTarget(r *http.Request, raw string) (string, error) {
	t, err := api.BanTargetFromRequest(r, raw)
	if err != nil {
		return "", fmt.Errorf("%w", err)
	}
	if err := security.CheckBanWhitelist(h.DB, t); err != nil {
		return "", err
	}
	return t.Value, nil
}
