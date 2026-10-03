// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/sqltime"
)

const (
	traceDefaultDays = 30
	traceMaxScan     = 2_000_000
	traceMaxIPs      = 5000
	traceMaxSystem   = 500
)

// TraceStep est une étape du parcours d'une cible : un épisode d'activité, un ban, un déban,
// une détection ou un événement système.
type TraceStep struct {
	Kind        string               `json:"kind"` // activity | ban | unban | threat | system
	Ts          time.Time            `json:"ts"`
	End         *time.Time           `json:"end,omitempty"`
	IP          string               `json:"ip,omitempty"`
	Domain      string               `json:"domain,omitempty"`
	Source      string               `json:"source,omitempty"`
	Reason      string               `json:"reason,omitempty"`
	Occurrences int                  `json:"occurrences,omitempty"`
	Burst       *security.TraceBurst `json:"burst,omitempty"`
}

type traceDay struct {
	Day      string `json:"day"`
	Requests int    `json:"requests"`
	Blocked  int    `json:"blocked"`
}

type traceBan struct {
	ID        string `json:"id"`
	IP        string `json:"ip"`
	Domain    string `json:"domain"`
	Reason    string `json:"reason"`
	Source    string `json:"source"`
	ExpiresAt string `json:"expires_at,omitempty"`
}

type traceProfile struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Mode string `json:"mode"`
}

// TraceQuery borne un parcours : cible, période (from < to), tri et page.
type TraceQuery struct {
	Target   netip.Prefix
	From, To time.Time
	Desc     bool
	Limit    int
	Offset   int
}

// ParseTraceQuery lit target (ou ip), from, to (RFC3339 ou AAAA-MM-JJ, défaut : 30 derniers jours),
// limit (défaut 500, max 2000) et offset ; order vaut asc (défaut) ou desc.
func ParseTraceQuery(get func(string) string) (TraceQuery, error) {
	raw := get("target")
	if raw == "" {
		raw = get("ip")
	}
	target, err := security.ParseTraceTarget(raw)
	if err != nil {
		return TraceQuery{}, err
	}
	now := time.Now().UTC()
	to, err := parseTraceBound(get("to"), now, true)
	if err != nil {
		return TraceQuery{}, err
	}
	from, err := parseTraceBound(get("from"), now.AddDate(0, 0, -traceDefaultDays), false)
	if err != nil {
		return TraceQuery{}, err
	}
	if !from.Before(to) {
		return TraceQuery{}, errBadTraceRange
	}
	qy := TraceQuery{Target: target, From: from, To: to, Desc: get("order") == "desc", Limit: 500}
	if v, _ := strconv.Atoi(get("limit")); v > 0 && v <= 2000 {
		qy.Limit = v
	}
	if v, _ := strconv.Atoi(get("offset")); v > 0 {
		qy.Offset = v
	}
	return qy, nil
}

// ipTrace : GET /api/v1/security/ip-trace?target=<ip|cidr>&from=&to=&order=asc|desc&limit=&offset=
func (h *SecurityHandler) ipTrace(w http.ResponseWriter, r *http.Request) {
	qy, err := ParseTraceQuery(r.URL.Query().Get)
	if err != nil {
		secJSONErr(w, err, http.StatusBadRequest)
		return
	}
	res, err := TraceIP(r.Context(), h.DB, qy)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	jsonOK(w, res)
}

// TraceIP reconstitue, sur toute la période demandée, ce qu'une IP ou un CIDR a fait : requêtes
// (regroupées en épisodes), détections WAF/Sentinel, bans et débans, présence dans un profil IP.
// Les requêtes ne remontent pas plus loin que la rétention des logs d'accès ; les bans et menaces
// ont leur propre rétention.
func TraceIP(ctx context.Context, db *sql.DB, qy TraceQuery) (map[string]any, error) {
	target, from, to, limit, offset := qy.Target, qy.From, qy.To, qy.Limit, qy.Offset
	var steps []TraceStep
	sum := struct {
		FirstSeen    *time.Time            `json:"first_seen"`
		LastSeen     *time.Time            `json:"last_seen"`
		Requests     int                   `json:"requests"`
		Blocked      int                   `json:"blocked"`
		IPCount      int                   `json:"ip_count"`
		TopIPs       []security.TraceCount `json:"top_ips"`
		TopDomains   []security.TraceCount `json:"top_domains"`
		TopPaths     []security.TraceCount `json:"top_paths"`
		Statuses     map[string]int        `json:"statuses"`
		WAFMatches   []security.TraceCount `json:"waf_matches"`
		ThreatSignal []security.TraceCount `json:"threat_signals"`
		Countries    []security.TraceCount `json:"countries"`
		Bans         int                   `json:"bans"`
		Unbans       int                   `json:"unbans"`
		Threats      int                   `json:"threats"`
		Episodes     int                   `json:"episodes"`
		Days         []traceDay            `json:"days"`
		ActiveBans   []traceBan            `json:"active_bans"`
		Profiles     []traceProfile        `json:"profiles"`
		ScanLimited  bool                  `json:"scan_limited"`
	}{Statuses: map[string]int{}}
	seen := func(t time.Time) {
		if sum.FirstSeen == nil || t.Before(*sum.FirstSeen) {
			c := t
			sum.FirstSeen = &c
		}
		if sum.LastSeen == nil || t.After(*sum.LastSeen) {
			c := t
			sum.LastSeen = &c
		}
	}

	// ── Requêtes d'accès, regroupées en épisodes ──────────────────────────────
	query := `SELECT ts, ip, domain, method, path, status, node_name, COALESCE(waf_matches,''),
	                 COALESCE(threat_signal,''), component, level, message
	          FROM logs WHERE ts >= ? AND ts <= ?`
	args := []any{from.Format(time.RFC3339), to.Format(time.RFC3339Nano)}
	if lo, hi, ok := security.TraceIPRange(target); ok {
		query += ` AND ip >= ? AND ip < ?`
		args = append(args, lo, hi)
	}
	rows, err := db.QueryContext(ctx, query+` ORDER BY ts ASC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()

	var bb security.BurstBuilder
	ipHits := map[string]int{}
	domains, paths, waf, sig := map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	days := map[string]*traceDay{}
	scanned, systemSteps := 0, 0
	for rows.Next() {
		var ts, ip, domain, method, path, node, wafJSON, signal, component, level, message string
		var status int
		if rows.Scan(&ts, &ip, &domain, &method, &path, &status, &node, &wafJSON, &signal, &component, &level, &message) != nil {
			continue
		}
		if !security.TraceMatch(target, ip) {
			continue
		}
		if scanned++; scanned > traceMaxScan {
			sum.ScanLimited = true
			break
		}
		t, err := time.Parse(time.RFC3339Nano, ts)
		if err != nil {
			continue
		}
		t = t.UTC()
		seen(t)
		if _, ok := ipHits[ip]; ok || len(ipHits) < traceMaxIPs {
			ipHits[ip]++
		}
		if status == 0 {
			if systemSteps++; systemSteps <= traceMaxSystem {
				steps = append(steps, TraceStep{Kind: "system", Ts: t, IP: ip, Domain: domain, Source: component, Reason: level + " · " + message})
			}
			continue
		}
		var matches []string
		if wafJSON != "" {
			json.Unmarshal([]byte(wafJSON), &matches) //nolint:errcheck
		}
		req := security.TraceRequest{Ts: t, IP: ip, Domain: domain, Method: method, Path: path, Status: status, Node: node, WAFMatches: matches, ThreatSignal: signal}
		bb.Add(req)
		blocked := status == 403 || status == 429 || len(matches) > 0 || signal != ""
		sum.Requests++
		sum.Statuses[strconv.Itoa(status/100)+"xx"]++
		if blocked {
			sum.Blocked++
		}
		if domain != "" {
			domains[domain]++
		}
		if path != "" {
			paths[method+" "+path]++
		}
		for _, m := range matches {
			waf[m]++
		}
		if signal != "" {
			sig[signal]++
		}
		day := ts[:10]
		d := days[day]
		if d == nil {
			d = &traceDay{Day: day}
			days[day] = d
		}
		d.Requests++
		if blocked {
			d.Blocked++
		}
	}
	rows.Close()
	bb.Done()
	sum.Episodes = len(bb.Bursts)
	for _, b := range bb.Bursts {
		end := b.End
		steps = append(steps, TraceStep{Kind: "activity", Ts: b.Start, End: &end, Burst: b})
	}

	// ── Bans et débans ────────────────────────────────────────────────────────
	if hr, err := db.QueryContext(ctx,
		`SELECT ip, domain, action, reason, source, created_at FROM security_ban_history
		 WHERE created_at >= ? AND created_at <= ? ORDER BY created_at ASC`,
		sqltime.Format(from), sqltime.Format(to)); err == nil {
		defer hr.Close()
		for hr.Next() {
			var ip, domain, action, reason, source, ts string
			if hr.Scan(&ip, &domain, &action, &reason, &source, &ts) != nil || !security.TraceOverlap(target, ip) {
				continue
			}
			t, err := sqltime.Parse(ts)
			if err != nil {
				continue
			}
			kind := "ban"
			if action == "unbanned" {
				kind = "unban"
				sum.Unbans++
			} else {
				sum.Bans++
			}
			seen(t)
			steps = append(steps, TraceStep{Kind: kind, Ts: t.UTC(), IP: ip, Domain: domain, Source: source, Reason: reason})
		}
	}

	// ── Détections (CrowdSec, Sentinel…) ──────────────────────────────────────
	if tr, err := db.QueryContext(ctx,
		`SELECT ip, scenario, origin, type, occurrences, created_at, last_seen_at FROM security_threats
		 WHERE last_seen_at >= ? AND created_at <= ? ORDER BY created_at ASC`,
		sqltime.Format(from), sqltime.Format(to)); err == nil {
		defer tr.Close()
		for tr.Next() {
			var ip, scenario, origin, typ, created, last string
			var occ int
			if tr.Scan(&ip, &scenario, &origin, &typ, &occ, &created, &last) != nil || !security.TraceOverlap(target, ip) {
				continue
			}
			t, err := sqltime.Parse(created)
			if err != nil {
				continue
			}
			sum.Threats++
			seen(t)
			steps = append(steps, TraceStep{Kind: "threat", Ts: t.UTC(), IP: ip, Source: origin, Reason: scenario, Occurrences: occ})
			if l, err := sqltime.Parse(last); err == nil {
				seen(l)
			}
		}
	}

	// ── État actuel : bans en cours et profils IP qui contiennent la cible ───────
	if br, err := db.QueryContext(ctx,
		`SELECT id, ip, domain, reason, source, COALESCE(expires_at,'') FROM security_bans
		 WHERE expires_at IS NULL OR expires_at = '' OR datetime(expires_at) > CURRENT_TIMESTAMP`); err == nil {
		defer br.Close()
		for br.Next() {
			var b traceBan
			if br.Scan(&b.ID, &b.IP, &b.Domain, &b.Reason, &b.Source, &b.ExpiresAt) == nil && security.TraceOverlap(target, b.IP) {
				sum.ActiveBans = append(sum.ActiveBans, b)
			}
		}
	}
	if pr, err := db.QueryContext(ctx, `SELECT id, name, mode, cidrs FROM ip_profiles WHERE enabled=1`); err == nil {
		defer pr.Close()
		for pr.Next() {
			var p traceProfile
			var cidrsJSON string
			if pr.Scan(&p.ID, &p.Name, &p.Mode, &cidrsJSON) != nil {
				continue
			}
			var cidrs []string
			json.Unmarshal([]byte(cidrsJSON), &cidrs) //nolint:errcheck
			for _, c := range cidrs {
				if security.TraceOverlap(target, c) {
					sum.Profiles = append(sum.Profiles, p)
					break
				}
			}
		}
	}

	// ── Agrégats ──────────────────────────────────────────────────────────────
	sum.IPCount = len(ipHits)
	sum.TopIPs = security.TopCounts(ipHits, 10)
	sum.TopDomains = security.TopCounts(domains, 10)
	sum.TopPaths = security.TopCounts(paths, 10)
	sum.WAFMatches = security.TopCounts(waf, 10)
	sum.ThreatSignal = security.TopCounts(sig, 10)
	sum.Countries = traceCountries(ctx, db, ipHits)
	sum.Days = make([]traceDay, 0, len(days))
	for _, d := range days {
		sum.Days = append(sum.Days, *d)
	}
	sort.Slice(sum.Days, func(i, j int) bool { return sum.Days[i].Day < sum.Days[j].Day })

	sort.SliceStable(steps, func(i, j int) bool { return steps[i].Ts.Before(steps[j].Ts) })
	if qy.Desc {
		for i, j := 0, len(steps)-1; i < j; i, j = i+1, j-1 {
			steps[i], steps[j] = steps[j], steps[i]
		}
	}
	total := len(steps)
	if offset > total {
		offset = total
	}
	end := offset + limit
	if end > total {
		end = total
	}
	page := steps[offset:end]
	if page == nil {
		page = []TraceStep{}
	}
	kind := "ip"
	if target.Bits() != target.Addr().BitLen() {
		kind = "cidr"
	}
	return map[string]any{
		"target":      target.String(),
		"kind":        kind,
		"from":        from,
		"to":          to,
		"summary":     sum,
		"steps":       page,
		"total_steps": total,
		"offset":      offset,
		"has_more":    end < total,
	}, nil
}

// traceCountries résout le pays des IP observées depuis geoip_cache (sans appel réseau).
func traceCountries(ctx context.Context, db *sql.DB, ipHits map[string]int) []security.TraceCount {
	top := security.TopCounts(ipHits, 50)
	if len(top) == 0 {
		return []security.TraceCount{}
	}
	marks := make([]string, len(top))
	args := make([]any, len(top))
	for i, t := range top {
		marks[i], args[i] = "?", t.Value
	}
	rows, err := db.QueryContext(ctx,
		`SELECT ip, country_code FROM geoip_cache WHERE country_code != '' AND ip IN (`+strings.Join(marks, ",")+`)`, args...)
	if err != nil {
		return []security.TraceCount{}
	}
	defer rows.Close()
	byCountry := map[string]int{}
	for rows.Next() {
		var ip, cc string
		if rows.Scan(&ip, &cc) == nil {
			byCountry[cc] += ipHits[ip]
		}
	}
	return security.TopCounts(byCountry, 10)
}

var errBadTraceRange = traceErr("from doit précéder to")

type traceErr string

func (e traceErr) Error() string { return string(e) }

// parseTraceBound lit une borne RFC3339 ou AAAA-MM-JJ ; une date seule vaut minuit, ou la fin
// de journée pour la borne haute (endOfDay) afin d'inclure le jour demandé.
func parseTraceBound(s string, def time.Time, endOfDay bool) (time.Time, error) {
	if s == "" {
		return def, nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t.UTC(), nil
	}
	t, err := time.Parse("2006-01-02", s)
	if err != nil {
		return time.Time{}, traceErr("date invalide (RFC3339 ou AAAA-MM-JJ attendu) : " + s)
	}
	if endOfDay {
		t = t.Add(24*time.Hour - time.Nanosecond)
	}
	return t.UTC(), nil
}
