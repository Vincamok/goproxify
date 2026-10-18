// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"sort"
	"strconv"
	"time"
)

const (
	wafActivityDefaultHours = 24
	wafActivityMaxHours     = 168
	wafActivityMaxRows      = 50000
	wafActivityTop          = 8
)

// WAFCount est un compteur nommé (règle ou domaine).
type WAFCount struct {
	Name  string `json:"name"`
	Count int    `json:"count"`
}

// WAFActivity résume les requêtes que le WAF a signalées sur une fenêtre récente.
type WAFActivity struct {
	Hours int `json:"hours"`
	// Requests : requêtes signalées ; Blocked : celles refusées (403) ; Detected : les autres, passées.
	Requests   int        `json:"requests"`
	Blocked    int        `json:"blocked"`
	Detected   int        `json:"detected"`
	TopRules   []WAFCount `json:"top_rules"`
	TopDomains []WAFCount `json:"top_domains"`
	// Truncated : la fenêtre dépasse wafActivityMaxRows, les plus récentes seules sont comptées.
	Truncated bool `json:"truncated,omitempty"`
}

// ComputeWAFActivity compte les requêtes signalées depuis since, pour une passerelle (nodeName) ou toutes.
func ComputeWAFActivity(ctx context.Context, db *sql.DB, since time.Time, nodeName string) (WAFActivity, error) {
	q := `SELECT domain, status, waf_matches FROM logs INDEXED BY idx_logs_waf_ts
	      WHERE waf_matches != '' AND ts >= ?`
	args := []any{since.UTC().Format(time.RFC3339)}
	if nodeName != "" {
		q += ` AND node_name = ?`
		args = append(args, nodeName)
	}
	q += ` ORDER BY ts DESC LIMIT ?`
	args = append(args, wafActivityMaxRows+1)
	rows, err := db.QueryContext(ctx, q, args...)
	if err != nil {
		return WAFActivity{}, err
	}
	defer rows.Close()

	out := WAFActivity{}
	rules, domains := map[string]int{}, map[string]int{}
	for rows.Next() {
		var domain, matches string
		var status int
		if rows.Scan(&domain, &status, &matches) != nil {
			continue
		}
		var ids []string
		if json.Unmarshal([]byte(matches), &ids) != nil || len(ids) == 0 {
			continue
		}
		if out.Requests == wafActivityMaxRows {
			out.Truncated = true
			break
		}
		out.Requests++
		if status == http.StatusForbidden {
			out.Blocked++
		} else {
			out.Detected++
		}
		for _, id := range ids {
			rules[id]++
		}
		if domain != "" {
			domains[domain]++
		}
	}
	if err := rows.Err(); err != nil {
		return WAFActivity{}, err
	}
	out.TopRules, out.TopDomains = topCounts(rules), topCounts(domains)
	return out, nil
}

func topCounts(m map[string]int) []WAFCount {
	out := make([]WAFCount, 0, len(m))
	for k, v := range m {
		out = append(out, WAFCount{Name: k, Count: v})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Name < out[j].Name
	})
	if len(out) > wafActivityTop {
		out = out[:wafActivityTop]
	}
	return out
}

// getWAFActivity GET /api/v1/security/waf-activity?hours=24&edge=… : requêtes signalées par le WAF.
func (h *SecurityHandler) getWAFActivity(w http.ResponseWriter, r *http.Request) {
	hours := wafActivityDefaultHours
	if v, err := strconv.Atoi(r.URL.Query().Get("hours")); err == nil && v > 0 {
		hours = min(v, wafActivityMaxHours)
	}
	var node string
	if e := r.URL.Query().Get("edge"); e != "" {
		node = e
		var name string
		if h.DB.QueryRowContext(r.Context(), `SELECT node_name FROM tokens WHERE id=? OR node_name=? LIMIT 1`, e, e).Scan(&name) == nil && name != "" {
			node = name
		}
	}
	act, err := ComputeWAFActivity(r.Context(), h.DB, time.Now().Add(-time.Duration(hours)*time.Hour), node)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	act.Hours = hours
	jsonOK(w, act)
}
