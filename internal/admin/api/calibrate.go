// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// CalibDefaultHours et CalibMaxHours : la fenêtre rejouée par le calibrage. Une semaine par défaut : un créneau saisonnier a besoin de
// jours de trafic pour être jugé.
const (
	CalibDefaultHours = 168
	CalibMaxHours     = 168
)

// CalibrateEphor rejoue, sur chaque passerelle (ou sur edgeParam), ses accès récents avec une grille de réglages des valeurs de départ de
// l'ADR 0020 (référence saisonnière, énumération, empreintes TLS) et rend, par passerelle, ce que chaque réglage aurait signalé et celui
// qui est proposé. Ne modifie rien. cfgKey désigne la configuration d'Ephor dont on reprend les heures d'observation d'un créneau.
func CalibrateEphor(ctx context.Context, db *sql.DB, edge *prismedge.Source, cfgKey, edgeParam string, hours int, domain string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	if hours <= 0 {
		hours = CalibDefaultHours
	}
	if hours > CalibMaxHours {
		hours = CalibMaxHours
	}
	var cur threat.Config
	var raw string
	if db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, cfgKey).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &cur)
	}
	req := logapi.EphorCalibrateRequest{Hours: hours, Domain: domain, MinHours: cur.Seasonal.MinHours, EnumWindowSeconds: int(cur.Enumeration.Window.Seconds())}
	gws, meta, err := edge.Calibrate(ctx, gatewayName(ctx, db, edgeParam), req)
	if err != nil {
		return nil, err
	}
	return withMeta(map[string]any{
		"window_hours": hours, "domain": domain, "gateways": gws,
		"note": "Chaque passerelle est calibrée sur son propre trafic. La période rejouée est supposée ordinaire : une vraie attaque dans la fenêtre compte comme un faux positif, d'où la liste de ce que chaque réglage aurait signalé. Ne modifie aucune configuration.",
	}, meta), nil
}

// calibrateThreat : POST /api/v1/security/threat-config/calibrate[?edge=<passerelle>] — corps facultatif {hours, domain}.
func (h *SecurityHandler) calibrateThreat(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Hours  int    `json:"hours"`
		Domain string `json:"domain"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<12)).Decode(&body)
	}
	scope, ref := h.scope(r)
	out, err := CalibrateEphor(r.Context(), h.DB, h.Edge, threatConfigKey(scope), ref, body.Hours, body.Domain)
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}
