// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"math"
	"net/http"
	"sort"
	"strconv"
	"time"

	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

// Seuils proposés à partir des cumuls par minute de l'ADR 0010 (ADR 0011, étape 4) : ils ne contiennent aucune IP, donc on ne
// peut proposer que ce qui se lit sans elle — le plafond global de débit d'une passerelle. L'Admin ne pousse rien : il propose,
// l'administrateur accepte (le formulaire de réglages reçoit la valeur, il l'enregistre ou non). Les références par IP, elles,
// s'apprennent sur la passerelle.
const (
	suggestMinDays       = 14
	suggestMinMinutes    = 6 * 60 // en dessous, trop peu de trafic observé pour proposer quoi que ce soit
	suggestBurstFactor   = 4.0    // une minute moyenne cache des pointes : la limite vise quatre fois le 99,9ᵉ centile
	suggestMinGlobalRPS  = 20.0
	suggestDefaultWindow = 7
)

// ThresholdSuggestion décrit, pour une passerelle, le trafic normal observé et la limite globale qu'on peut en tirer.
type ThresholdSuggestion struct {
	NodeName         string  `json:"node_name"`
	Days             int     `json:"days"`
	MinutesObserved  int     `json:"minutes_observed"`
	Ready            bool    `json:"ready"`
	RPSMedian        float64 `json:"rps_median"`
	RPS99            float64 `json:"rps_p99"`
	RPS999           float64 `json:"rps_p999"`
	RPSMax           float64 `json:"rps_max"`
	ErrorShare       float64 `json:"error_share"` // part moyenne de 4xx et 5xx, en pourcentage
	CurrentGlobalRPS float64 `json:"current_global_rps"`
	SuggestedRPS     float64 `json:"suggested_global_rps,omitempty"`
	Why              string  `json:"why,omitempty"`
}

// SuggestEphorThresholds lit logs_minute et propose une limite globale par passerelle. days : fenêtre lue (7 par défaut, 90 au plus).
func SuggestEphorThresholds(ctx context.Context, db *sql.DB, cfgKey string, days int) ([]ThresholdSuggestion, error) {
	if days <= 0 {
		days = suggestDefaultWindow
	}
	if days > 90 {
		days = 90
	}
	var current threat.Config
	var raw string
	if db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, cfgKey).Scan(&raw) == nil {
		_ = json.Unmarshal([]byte(raw), &current)
	}

	from := logs.MinuteKey(time.Now().AddDate(0, 0, -days))
	rows, err := db.QueryContext(ctx, `
		SELECT node_name, minute, SUM(requests), SUM(CASE WHEN status >= 400 THEN requests ELSE 0 END)
		FROM logs_minute WHERE minute >= ? GROUP BY node_name, minute ORDER BY node_name`, from)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	type acc struct {
		perMinute    []float64
		requests, er float64
	}
	by := map[string]*acc{}
	var order []string
	for rows.Next() {
		var node, minute string
		var req, errs float64
		if err := rows.Scan(&node, &minute, &req, &errs); err != nil {
			return nil, err
		}
		a := by[node]
		if a == nil {
			a = &acc{}
			by[node] = a
			order = append(order, node)
		}
		a.perMinute = append(a.perMinute, req/60)
		a.requests += req
		a.er += errs
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	sort.Strings(order)
	out := make([]ThresholdSuggestion, 0, len(order))
	for _, node := range order {
		a := by[node]
		sort.Float64s(a.perMinute)
		s := ThresholdSuggestion{
			NodeName: node, Days: days, MinutesObserved: len(a.perMinute), CurrentGlobalRPS: current.GlobalRPS,
			RPSMedian: round2(percentile(a.perMinute, 0.5)), RPS99: round2(percentile(a.perMinute, 0.99)),
			RPS999: round2(percentile(a.perMinute, 0.999)), RPSMax: round2(a.perMinute[len(a.perMinute)-1]),
		}
		if a.requests > 0 {
			s.ErrorShare = round2(100 * a.er / a.requests)
		}
		if len(a.perMinute) < suggestMinMinutes {
			s.Why = "trop peu de trafic observé (au moins " + strconv.Itoa(suggestMinMinutes/60) + " h de minutes actives)"
		} else {
			s.Ready = true
			s.SuggestedRPS = niceCeil(math.Max(s.RPS999*suggestBurstFactor, suggestMinGlobalRPS))
			s.Why = "quatre fois le 99,9ᵉ centile du débit par minute sur " + strconv.Itoa(days) + " jours, arrondi au palier supérieur"
		}
		out = append(out, s)
	}
	return out, nil
}

func percentile(sorted []float64, p float64) float64 {
	if len(sorted) == 0 {
		return 0
	}
	i := int(math.Ceil(p*float64(len(sorted)))) - 1
	if i < 0 {
		i = 0
	}
	if i >= len(sorted) {
		i = len(sorted) - 1
	}
	return sorted[i]
}

func round2(v float64) float64 { return math.Round(v*100) / 100 }

// niceCeil arrondit au palier 1, 2, 5 × 10ⁿ supérieur : une limite lisible plutôt que 137,4.
func niceCeil(v float64) float64 {
	if v <= 0 {
		return 0
	}
	exp := math.Pow(10, math.Floor(math.Log10(v)))
	for _, m := range []float64{1, 2, 5, 10} {
		if v <= m*exp {
			return m * exp
		}
	}
	return 10 * exp
}

func (h *SecurityHandler) suggestThreatThresholds(w http.ResponseWriter, r *http.Request) {
	scope, _ := h.scope(r)
	days, _ := strconv.Atoi(r.URL.Query().Get("days"))
	out, err := SuggestEphorThresholds(r.Context(), h.DB, threatConfigKey(scope), days)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, map[string]any{"suggestions": out, "note": "Proposé à partir des cumuls par minute (sans IP) ; rien n'est appliqué. " +
		"Les seuils par IP s'apprennent sur la passerelle (références apprises)."})
}
