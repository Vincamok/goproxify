// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

func init() {
	tools = append(tools, map[string]any{
		"name": "calibrate_ephor",
		"description": "Calibre sur le trafic réel de chaque passerelle les valeurs de départ de l'ADR 0020 (référence saisonnière, détection d'énumération, réputation des empreintes TLS). " +
			"Chaque passerelle rejoue ses accès récents (une semaine par défaut) avec une grille de réglages et dit, pour chacun, ce qu'il aurait signalé : référence saisonnière " +
			"(plancher en req/s, multiple de la fenêtre rapide, écarts-types de la fenêtre lente : avertissements, attaques probables, minutes d'alerte), plancher d'énumération (couples IP/gabarit " +
			"signalés), empreintes TLS hors navigateurs et leur part d'erreurs. Propose le réglage le plus sensible qui n'aurait pas dépassé un petit budget d'alertes sur la période, et " +
			"liste ce que le réglage proposé aurait signalé pour que l'on juge si ce sont de vrais pics ou parcours. La période est supposée ordinaire : une vraie attaque dans la fenêtre " +
			"compte comme un faux positif. `warm_routes` à 0 : la fenêtre est trop courte pour juger quoi que ce soit, aucune recommandation. Chaque passerelle est calibrée sur son propre " +
			"trafic. Ne modifie rien ; les réglages se posent ensuite par la configuration d'Ephor (`seasonal`, `enumeration`), en detect d'abord.",
		"inputSchema": schema(
			opt("hours", "number", "Fenêtre rejouée en heures (défaut 168, max 168)"),
			opt("domain", "string", "Limiter le rejeu à un domaine"),
			opt("edge", "string", "Passerelle (nom du nœud ou id du token) ; défaut : toutes"),
		),
	})
}

func (h *Handler) toolCalibrateEphor(r *http.Request, args map[string]any) (any, error) {
	hours := api.CalibDefaultHours
	if v, ok := args["hours"].(float64); ok && v > 0 {
		hours = int(v)
	}
	domain, _ := args["domain"].(string)
	edgeID, _ := args["edge"].(string)
	return api.CalibrateEphor(r.Context(), h.DB, &prismedge.Source{DB: h.DB}, h.threatConfigKey(edgeID), edgeID, hours, domain)
}
