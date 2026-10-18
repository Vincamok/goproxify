// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func wafActivityTools() []map[string]any {
	return []map[string]any{{
		"name": "get_waf_activity",
		"description": "Activité du WAF sur les dernières heures : requêtes signalées (refusées en 403 ou passées en mode détection), " +
			"règles les plus déclenchées et domaines les plus visés. Sert à repérer des faux positifs avant de couper le WAF d'une passerelle " +
			"(interrupteur maître, PUT /security/waf-config). Les identifiants de règle sont ceux du WAF, ou le nom d'un plugin de détection. " +
			"`truncated` : plus de 50 000 requêtes signalées dans la fenêtre, seules les plus récentes sont comptées. Lecture seule.",
		"inputSchema": schema(
			opt("hours", "number", "Fenêtre en heures (défaut 24, max 168)"),
			opt("edge", "string", "ID du jeton ou nom de la passerelle (défaut : toutes)"),
		),
	}}
}

func init() { tools = append(tools, wafActivityTools()...) }

func (h *Handler) toolGetWAFActivity(r *http.Request, args map[string]any) (any, error) {
	hours, _ := args["hours"].(float64)
	edge, _ := args["edge"].(string)
	return api.WAFActivityFor(r.Context(), h.DB, int(hours), edge)
}
