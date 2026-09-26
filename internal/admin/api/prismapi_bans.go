// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net"
	"net/http"
	"sort"
	"strings"
	"time"
)

var prismSourceLabels = map[string]string{
	"threat":   "Sentinel",
	"fail2ban": "Fail2Ban",
	"crowdsec": "CrowdSec",
	"native":   "Manuel",
	"agent":    "Agent",
}

var sentinelTechniqueLabels = map[string]string{
	"ip":          "Liste d'IP malveillantes",
	"custom_ip":   "Liste d'IP personnalisée",
	"ua":          "User-Agent suspect",
	"custom_ua":   "User-Agent personnalisé",
	"path":        "Chemin sensible (scan)",
	"custom_path": "Chemin personnalisé",
	"rate":        "Débit excessif",
}

// banTechnique déduit la technique de détection d'un ban à partir de sa source et de sa raison.
func banTechnique(source, reason string) (key, label string) {
	reason = strings.TrimSpace(reason)
	switch source {
	case "threat":
		key = strings.TrimSpace(strings.TrimPrefix(reason, "threat:"))
		if l, ok := sentinelTechniqueLabels[key]; ok {
			return key, l
		}
	case "fail2ban":
		key = strings.TrimSpace(strings.TrimPrefix(reason, "Fail2Ban:"))
		if key == "trop d'erreurs" || key == "" {
			return "errors", "Trop d'erreurs HTTP"
		}
	}
	if key == "" {
		key = reason
	}
	if key == "" {
		return "unknown", "Non précisé"
	}
	return key, key
}

// bansBreakdown ventile les bans actifs par source puis par technique de détection.
func (h *PrismHandler) bansBreakdown(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT source, reason, COUNT(*) FROM security_bans
		WHERE expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP
		GROUP BY source, reason`)
	if err != nil {
		prismJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	defer rows.Close()
	type row struct {
		Source      string `json:"source"`
		SourceLabel string `json:"source_label"`
		Sentinel    bool   `json:"sentinel"`
		Technique   string `json:"technique"`
		Label       string `json:"label"`
		Count       int    `json:"count"`
	}
	agg := map[string]*row{}
	for rows.Next() {
		var src, reason string
		var n int
		if rows.Scan(&src, &reason, &n) != nil {
			continue
		}
		key, label := banTechnique(src, reason)
		k := src + "\x00" + key
		if cur, ok := agg[k]; ok {
			cur.Count += n
			continue
		}
		sl := prismSourceLabels[src]
		if sl == "" {
			sl = src
		}
		agg[k] = &row{Source: src, SourceLabel: sl, Sentinel: src == "threat", Technique: key, Label: label, Count: n}
	}
	out := make([]row, 0, len(agg))
	for _, v := range agg {
		out = append(out, *v)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Count > out[j].Count })
	jsonOK(w, out)
}

// ipScan ré-analyse une IP à la demande : bans actifs, historique, décisions de menace et activité récente.
func (h *PrismHandler) ipScan(w http.ResponseWriter, r *http.Request) {
	ip := strings.TrimSpace(r.URL.Query().Get("ip"))
	if net.ParseIP(ip) == nil {
		http.Error(w, "ip invalide", http.StatusBadRequest)
		return
	}
	ctx := r.Context()
	p := prismParams(r)

	type ban struct {
		Source      string `json:"source"`
		SourceLabel string `json:"source_label"`
		Sentinel    bool   `json:"sentinel"`
		Technique   string `json:"technique"`
		Reason      string `json:"reason"`
		Since       string `json:"since"`
		ExpiresAt   string `json:"expires_at,omitempty"`
	}
	type threat struct {
		Scenario    string `json:"scenario"`
		Origin      string `json:"origin"`
		Occurrences int    `json:"occurrences"`
		LastSeen    string `json:"last_seen"`
	}
	type pathStat struct {
		Path     string `json:"path"`
		Requests int    `json:"requests"`
		Errors   int    `json:"errors"`
	}
	out := struct {
		IP         string     `json:"ip"`
		ScannedAt  string     `json:"scanned_at"`
		Verdict    string     `json:"verdict"`
		Bans       []ban      `json:"bans"`
		BanHistory int        `json:"ban_history"`
		Threats    []threat   `json:"threats"`
		Requests   int        `json:"requests"`
		Errors     int        `json:"errors"`
		FirstSeen  string     `json:"first_seen,omitempty"`
		LastSeen   string     `json:"last_seen,omitempty"`
		TopPaths   []pathStat `json:"top_paths"`
	}{IP: ip, ScannedAt: time.Now().UTC().Format(time.RFC3339), Bans: []ban{}, Threats: []threat{}, TopPaths: []pathStat{}}

	if rows, err := h.DB.QueryContext(ctx, `
		SELECT source, reason, COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', created_at),''), COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', expires_at),'')
		FROM security_bans WHERE ip = ? AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		ORDER BY created_at DESC`, ip); err == nil {
		for rows.Next() {
			var b ban
			if rows.Scan(&b.Source, &b.Reason, &b.Since, &b.ExpiresAt) != nil {
				continue
			}
			b.Sentinel = b.Source == "threat"
			b.SourceLabel = prismSourceLabels[b.Source]
			if b.SourceLabel == "" {
				b.SourceLabel = b.Source
			}
			_, b.Technique = banTechnique(b.Source, b.Reason)
			out.Bans = append(out.Bans, b)
		}
		rows.Close()
	}
	h.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM security_ban_history WHERE ip = ? AND action = 'banned'`, ip).Scan(&out.BanHistory) //nolint:errcheck

	if rows, err := h.DB.QueryContext(ctx, `
		SELECT scenario, origin, occurrences, COALESCE(strftime('%Y-%m-%dT%H:%M:%SZ', last_seen_at),'')
		FROM security_threats WHERE ip = ? ORDER BY last_seen_at DESC LIMIT 10`, ip); err == nil {
		for rows.Next() {
			var t threat
			if rows.Scan(&t.Scenario, &t.Origin, &t.Occurrences, &t.LastSeen) == nil {
				out.Threats = append(out.Threats, t)
			}
		}
		rows.Close()
	}

	from, to := p.From.UTC().Format(time.RFC3339), p.To.UTC().Format(time.RFC3339)
	h.DB.QueryRowContext(ctx, `
		SELECT COUNT(*), COALESCE(SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),0), COALESCE(MIN(ts),''), COALESCE(MAX(ts),'')
		FROM logs WHERE ip = ? AND status > 0 AND ts >= ? AND ts <= ?`, ip, from, to).
		Scan(&out.Requests, &out.Errors, &out.FirstSeen, &out.LastSeen) //nolint:errcheck
	if rows, err := h.DB.QueryContext(ctx, `
		SELECT path, COUNT(*) n, SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END)
		FROM logs WHERE ip = ? AND status > 0 AND ts >= ? AND ts <= ?
		GROUP BY path ORDER BY n DESC LIMIT 5`, ip, from, to); err == nil {
		for rows.Next() {
			var ps pathStat
			if rows.Scan(&ps.Path, &ps.Requests, &ps.Errors) == nil {
				out.TopPaths = append(out.TopPaths, ps)
			}
		}
		rows.Close()
	}

	switch {
	case len(out.Bans) > 0:
		out.Verdict = "banned"
	case len(out.Threats) > 0 || out.BanHistory > 0 || (out.Requests >= 20 && out.Errors*2 >= out.Requests):
		out.Verdict = "suspect"
	default:
		out.Verdict = "clean"
	}
	jsonOK(w, out)
}
