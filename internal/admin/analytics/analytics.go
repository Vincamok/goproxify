// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package analytics agrège les données de la table logs pour Prism.
package analytics

import (
	"context"
	"database/sql"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"sort"
	"strings"
	"time"

)

const queryTimeout = 25 * time.Second

// Params filtre commun à toutes les requêtes.
type Params struct {
	Proxy    string // domaine ou "" pour tous
	NodeName string // nœud passerelle ou "" pour tous
	IP       string // IP client ou "" pour tous
	Path     string // préfixe/égalité chemin ou "" pour tous
	From     time.Time
	To       time.Time
}

// KPIs métriques globales pour la période.
type KPIs struct {
	Requests       int64   `json:"requests"`
	RequestsDelta  float64 `json:"requests_delta"`  // % vs période précédente
	Bandwidth      int64   `json:"bandwidth"`        // bytes
	BandwidthDelta float64 `json:"bandwidth_delta"`
	ErrorRate      float64 `json:"error_rate"` // % 4xx+5xx
	ErrorRateDelta float64 `json:"error_rate_delta"`
	UniqueIPs      int64   `json:"unique_ips"`
	AvgLatencyMs   float64 `json:"avg_latency_ms"`
	BotShare       float64 `json:"bot_share"` // % requests from known bots
}

// TimePoint point de la courbe temporelle.
type TimePoint struct {
	Bucket   string `json:"bucket"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"`
	Bytes    int64  `json:"bytes"`
}

// StatusGroup répartition par famille de codes HTTP.
type StatusGroup struct {
	Group    string         `json:"group"`    // "2xx" / "3xx" / "4xx" / "5xx"
	Count    int64          `json:"count"`
	Pct      float64        `json:"pct"`
	Breakdown []StatusEntry `json:"breakdown"`
}

// StatusEntry détail d'un code HTTP précis.
type StatusEntry struct {
	Code  int     `json:"code"`
	Count int64   `json:"count"`
	Pct   float64 `json:"pct"`
}

// PathEntry top chemin.
type PathEntry struct {
	Path      string  `json:"path"`
	Requests  int64   `json:"requests"`
	Errors    int64   `json:"errors"`
	AvgLatMs  float64 `json:"avg_lat_ms"`
	Bytes     int64   `json:"bytes"`
}

// IPEntry top IP.
type IPEntry struct {
	IP       string `json:"ip"`
	Requests int64  `json:"requests"`
	Errors   int64  `json:"errors"`
	Bytes    int64  `json:"bytes"`
	// IPTruncated : IP tronquée par l'anonymisation RGPD de la passerelle. La ligne regroupe tout
	// un /24 (IPv4) ou /48 (IPv6) : ni bannissable ni analysable comme un client.
	IPTruncated bool `json:"ip_truncated,omitempty"`
}

// AgentEntry navigateur ou bot.
type AgentEntry struct {
	Name     string  `json:"name"`
	Requests int64   `json:"requests"`
	Pct      float64 `json:"pct"`
	IsBot    bool    `json:"is_bot"`
}

// ProxyOption proxy disponible pour le filtre.
type ProxyOption struct {
	Domain string `json:"domain"`
	Name   string `json:"name"`
}

// domainCond construit la condition sur une colonne de domaine ; `proxy` peut lister
// plusieurs domaines séparés par des virgules (sélection multiple de la Vue Proxy).
func domainCond(col, proxy string) (string, []any) {
	var args []any
	for _, d := range strings.Split(proxy, ",") {
		if d = strings.TrimSpace(d); d != "" {
			args = append(args, d)
		}
	}
	switch len(args) {
	case 0:
		return "", nil
	case 1:
		return col + " = ?", args
	}
	return col + " IN (?" + strings.Repeat(",?", len(args)-1) + ")", args
}

// Totals sont les totaux d'une période : de quoi calculer les KPIs, quelle que soit la source (cumuls, lignes de l'Admin
// ou classement des passerelles).
type Totals struct {
	Requests, Bytes, Errors, Bots int64
	AvgLatencyMs                  float64
}

// PreviousPeriod rend la période qui précède p, de même durée. Les cumuls sont à la minute et incluent les deux bornes :
// la période précédente s'arrête avant la minute où la courante commence, sinon cette minute compterait dans les deux.
func PreviousPeriod(p Params, onMinutes bool) Params {
	dur := p.To.Sub(p.From)
	prev := Params{Proxy: p.Proxy, NodeName: p.NodeName, From: p.From.Add(-dur), To: p.From.Add(-time.Second)}
	if onMinutes {
		prev.To = p.From.Truncate(time.Minute).Add(-time.Second)
	}
	return prev
}

// BuildKPIs calcule les KPIs et leurs écarts avec la période précédente.
func BuildKPIs(cur, prev Totals, uniqueIPs int64) KPIs {
	errRate, preErrRate := 0.0, 0.0
	if cur.Requests > 0 {
		errRate = float64(cur.Errors) / float64(cur.Requests) * 100
	}
	if prev.Requests > 0 {
		preErrRate = float64(prev.Errors) / float64(prev.Requests) * 100
	}
	pct := func(c, p int64) float64 {
		if p == 0 {
			return 0
		}
		return float64(c-p) / float64(p) * 100
	}
	pctF := func(c, p float64) float64 {
		if p == 0 {
			return 0
		}
		return (c - p) / p * 100
	}
	botShare := 0.0
	if cur.Requests > 0 {
		botShare = float64(cur.Bots) / float64(cur.Requests) * 100
	}
	return KPIs{
		Requests:       cur.Requests,
		RequestsDelta:  pct(cur.Requests, prev.Requests),
		Bandwidth:      cur.Bytes,
		BandwidthDelta: pct(cur.Bytes, prev.Bytes),
		ErrorRate:      errRate,
		ErrorRateDelta: pctF(errRate, preErrRate),
		UniqueIPs:      uniqueIPs,
		AvgLatencyMs:   cur.AvgLatencyMs,
		BotShare:       botShare,
	}
}

// StatusGroupsFromCounts répartit des requêtes par code HTTP en familles (2xx à 5xx) avec le détail de chaque code.
func StatusGroupsFromCounts(counts map[int]int64) []StatusGroup {
	type codeCnt struct {
		code  int
		count int64
	}
	groups := map[string][]codeCnt{"2xx": {}, "3xx": {}, "4xx": {}, "5xx": {}}
	codes := make([]int, 0, len(counts))
	var total int64
	for code, cnt := range counts {
		codes = append(codes, code)
		total += cnt
	}
	sort.Ints(codes)
	for _, code := range codes {
		cnt := counts[code]
		switch {
		case code >= 200 && code < 300:
			groups["2xx"] = append(groups["2xx"], codeCnt{code, cnt})
		case code >= 300 && code < 400:
			groups["3xx"] = append(groups["3xx"], codeCnt{code, cnt})
		case code >= 400 && code < 500:
			groups["4xx"] = append(groups["4xx"], codeCnt{code, cnt})
		case code >= 500:
			groups["5xx"] = append(groups["5xx"], codeCnt{code, cnt})
		}
	}
	var out []StatusGroup
	for _, g := range []string{"2xx", "3xx", "4xx", "5xx"} {
		cs := groups[g]
		var gTotal int64
		for _, c := range cs {
			gTotal += c.count
		}
		sg := StatusGroup{Group: g, Count: gTotal}
		if total > 0 {
			sg.Pct = float64(gTotal) / float64(total) * 100
		}
		for _, c := range cs {
			pct := 0.0
			if gTotal > 0 {
				pct = float64(c.count) / float64(gTotal) * 100
			}
			sg.Breakdown = append(sg.Breakdown, StatusEntry{Code: c.code, Count: c.count, Pct: pct})
		}
		out = append(out, sg)
	}
	return out
}

// MinutePoint : le trafic d'une minute (UTC, AAAA-MM-JJTHH:MM), tel que les passerelles le rendent pour une sélection.
type MinutePoint struct {
	Minute   string
	Requests int64
	Errors   int64
	Bytes    int64
}

// TimelineFromMinutes regroupe des minutes en points de la courbe (heure locale du serveur, comme GetTimeline) :
// bucket vaut "minute", "hour" ou "day".
func TimelineFromMinutes(points []MinutePoint, bucket string) []TimePoint {
	layout := "2006-01-02T15:00"
	switch bucket {
	case "minute":
		layout = "2006-01-02T15:04"
	case "day":
		layout = "2006-01-02"
	}
	agg := map[string]*TimePoint{}
	for _, m := range points {
		t, err := time.Parse("2006-01-02T15:04", m.Minute)
		if err != nil {
			continue
		}
		key := t.Local().Format(layout)
		tp := agg[key]
		if tp == nil {
			tp = &TimePoint{Bucket: key}
			agg[key] = tp
		}
		tp.Requests += m.Requests
		tp.Errors += m.Errors
		tp.Bytes += m.Bytes
	}
	out := make([]TimePoint, 0, len(agg))
	for _, tp := range agg {
		out = append(out, *tp)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket < out[j].Bucket })
	return out
}

var botKeywords = []string{
	"bot", "crawler", "spider", "scraper", "wget", "curl", "python-requests",
	"go-http-client", "libwww", "httpclient", "nmap", "masscan", "zgrab",
	"nikto", "nuclei", "sqlmap", "dirbuster", "gobuster", "ffuf",
}

// IsBot dit si le nom ressemble à un robot connu.
func IsBot(agent string) bool { return isBot(agent) }

func isBot(agent string) bool {
	low := strings.ToLower(agent)
	for _, kw := range botKeywords {
		if strings.Contains(low, kw) {
			return true
		}
	}
	return false
}

// GetProxies retourne les domaines configurés (table proxies), sans scanner logs.
// Si nodeName est non vide, ne retourne que les domaines vus par cette passerelle dans les cumuls par minute (ses accès
// ordinaires ne sont plus dans la base de l'Admin).
func GetProxies(db *sql.DB, nodeName string) []ProxyOption {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	var (
		rows *sql.Rows
		err  error
	)
	if nodeName != "" {
		rows, err = db.QueryContext(ctx,
			`SELECT DISTINCT domain, domain
			 FROM logs_minute
			 WHERE node_name = ? AND domain != ''
			 ORDER BY domain`, nodeName)
	} else {
		// Les proxies TCP/UDP (config.host vide, voir router.Route) n'étaient jamais listés
		// (filtre host IS NOT NULL) — ils apparaissent maintenant, identifiés par leur nom
		// plutôt qu'un domaine qu'ils n'ont pas. Prism reste basé sur logs.domain (requêtes
		// HTTP) : sélectionner un proxy TCP/UDP ici ne fera remonter aucune donnée tant que
		// le flux L4 lui-même n'est pas journalisé par requête, mais au moins il est visible.
		rows, err = db.QueryContext(ctx,
			`SELECT
			   CASE WHEN json_extract(config,'$.host') IS NOT NULL AND json_extract(config,'$.host') != ''
			        THEN json_extract(config,'$.host') ELSE name END,
			   CASE WHEN json_extract(config,'$.host') IS NOT NULL AND json_extract(config,'$.host') != ''
			        THEN name ELSE name || ' (TCP/UDP)' END
			 FROM proxies
			 WHERE enabled = 1
			 ORDER BY name`)
	}
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []ProxyOption
	seen := map[string]bool{}
	for rows.Next() {
		var opt ProxyOption
		rows.Scan(&opt.Domain, &opt.Name) //nolint:errcheck
		if opt.Domain == "" || seen[opt.Domain] {
			continue
		}
		seen[opt.Domain] = true
		out = append(out, opt)
	}
	return out
}

// ReferrerEntry top référent.
type ReferrerEntry struct {
	Referrer string  `json:"referrer"`
	Requests int64   `json:"requests"`
	Pct      float64 `json:"pct"`
}

// ExportRow est une ligne d'un export de Prism.
type ExportRow struct {
	Ts        string `json:"ts"`
	Domain    string `json:"domain"`
	Method    string `json:"method"`
	Path      string `json:"path"`
	Status    int    `json:"status"`
	IP        string `json:"ip"`
	LatencyMs int64  `json:"latency_ms"`
	Bytes     int64  `json:"bytes"`
	Message   string `json:"message,omitempty"`
}

// ExportMaxRows borne les lignes d'un export.
const ExportMaxRows = 50000

// CSVFromRows met des lignes d'export en CSV.
func CSVFromRows(rows []ExportRow) []byte {
	var sb strings.Builder
	cw := csv.NewWriter(&sb)
	cw.Write([]string{"ts", "domain", "method", "path", "status", "ip", "latency_ms", "bytes", "message"}) //nolint:errcheck
	for _, r := range rows {
		cw.Write([]string{r.Ts, r.Domain, r.Method, r.Path, fmt.Sprintf("%d", r.Status), r.IP, fmt.Sprintf("%d", r.LatencyMs), fmt.Sprintf("%d", r.Bytes), r.Message}) //nolint:errcheck
	}
	cw.Flush()
	return []byte(sb.String())
}

// JSONFromRows met des lignes d'export en JSON.
func JSONFromRows(rows []ExportRow) ([]byte, error) { return json.MarshalIndent(rows, "", "  ") }

// HTMLReport met en page le rapport HTML de Prism.
func HTMLReport(p Params, kpis KPIs, timeline []TimePoint, statusGroups []StatusGroup, paths []PathEntry, ips []IPEntry) []byte {
	var sb strings.Builder
	sb.WriteString(`<!DOCTYPE html><html lang="fr"><head><meta charset="UTF-8"><title>Prism Report — Goproxify</title>
<style>body{font-family:system-ui,sans-serif;background:#0f1117;color:#e2e8f0;margin:0;padding:24px}
h1{font-size:22px;margin-bottom:4px}.sub{color:#64748b;font-size:13px;margin-bottom:24px}
.kpis{display:grid;grid-template-columns:repeat(auto-fill,minmax(140px,1fr));gap:12px;margin-bottom:24px}
.kpi{background:#1e2433;border:1px solid #2d3748;border-radius:8px;padding:14px}
.kpi-val{font-size:22px;font-weight:700;margin-bottom:2px}.kpi-lbl{font-size:11px;color:#64748b;text-transform:uppercase;letter-spacing:.5px}
table{width:100%;border-collapse:collapse;font-size:12px;margin-bottom:24px}
th{color:#64748b;font-weight:500;text-align:left;padding:6px 10px;border-bottom:1px solid #2d3748}
td{padding:5px 10px;border-bottom:1px solid #1e2433}
h2{font-size:15px;margin:24px 0 10px;color:#94a3b8}
.bb{display:inline-block;width:80px;height:6px;background:#2d3748;border-radius:3px;vertical-align:middle}
.bf{display:inline-block;height:100%;border-radius:3px;background:#6366f1;vertical-align:top}
.bfe{background:#ef4444}</style></head><body>`)

	proxy := p.Proxy
	if proxy == "" {
		proxy = "tous les proxies"
	}
	fmt.Fprintf(&sb, `<h1>Rapport Prism — Goproxify</h1><div class="sub">%s → %s &nbsp;|&nbsp; %s &nbsp;|&nbsp; Généré le %s</div>`,
		htmlEsc(p.From.Format("2006-01-02 15:04")), htmlEsc(p.To.Format("2006-01-02 15:04")),
		htmlEsc(proxy), time.Now().Format("2006-01-02 15:04:05"))

	// KPIs
	sb.WriteString(`<div class="kpis">`)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Requêtes</div><div class="kpi-val">%d</div></div>`, kpis.Requests)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Bande passante</div><div class="kpi-val">%s</div></div>`, htmlFmtBytes(kpis.Bandwidth))
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Taux erreur</div><div class="kpi-val">%.1f%%</div></div>`, kpis.ErrorRate)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">IPs uniques</div><div class="kpi-val">%d</div></div>`, kpis.UniqueIPs)
	fmt.Fprintf(&sb, `<div class="kpi"><div class="kpi-lbl">Latence moy.</div><div class="kpi-val">%.0f ms</div></div>`, kpis.AvgLatencyMs)
	sb.WriteString(`</div>`)

	// Timeline SVG
	if len(timeline) > 0 {
		maxR := int64(1)
		for _, pt := range timeline {
			if pt.Requests > maxR {
				maxR = pt.Requests
			}
		}
		W, H := 600.0, 80.0
		n := len(timeline)
		xStep := W / float64(n-1+1)
		if n > 1 { xStep = W / float64(n-1) }
		toY := func(v int64) float64 { return H - (float64(v)/float64(maxR))*(H-4) }
		var pathStr strings.Builder
		for i, pt := range timeline {
			if i == 0 {
				fmt.Fprintf(&pathStr, "M%.1f,%.1f", float64(i)*xStep, toY(pt.Requests))
			} else {
				fmt.Fprintf(&pathStr, " L%.1f,%.1f", float64(i)*xStep, toY(pt.Requests))
			}
		}
		fmt.Fprintf(&sb, `<h2>Requêtes / heure</h2><svg viewBox="0 0 %.0f %.0f" style="width:100%%;max-width:700px;height:%.0fpx;background:#1e2433;border-radius:8px;display:block;margin-bottom:16px"><path d="%s" fill="none" stroke="#6366f1" stroke-width="2"/></svg>`,
			W, H, H, pathStr.String())
	}

	// Status groups
	sb.WriteString(`<h2>Codes HTTP</h2><table><thead><tr><th>Famille</th><th>Requêtes</th><th>%</th></tr></thead><tbody>`)
	for _, g := range statusGroups {
		fmt.Fprintf(&sb, `<tr><td>%s</td><td>%d</td><td>%.1f%%</td></tr>`, g.Group, g.Count, g.Pct)
	}
	sb.WriteString(`</tbody></table>`)

	// Top paths
	maxP := int64(1)
	for _, p2 := range paths {
		if p2.Requests > maxP { maxP = p2.Requests }
	}
	sb.WriteString(`<h2>Top chemins</h2><table><thead><tr><th>Chemin</th><th>Req.</th><th>Err.</th><th>Lat.</th></tr></thead><tbody>`)
	for _, p2 := range paths {
		fmt.Fprintf(&sb, `<tr><td style="font-family:monospace;font-size:11px">%s</td><td>%d</td><td>%d</td><td>%.0f ms</td></tr>`,
			htmlEsc(p2.Path), p2.Requests, p2.Errors, p2.AvgLatMs)
	}
	sb.WriteString(`</tbody></table>`)

	// Top IPs
	sb.WriteString(`<h2>Top IPs</h2><table><thead><tr><th>IP</th><th>Req.</th><th>Err.</th></tr></thead><tbody>`)
	for _, i2 := range ips {
		fmt.Fprintf(&sb, `<tr><td style="font-family:monospace">%s</td><td>%d</td><td>%d</td></tr>`,
			htmlEsc(i2.IP), i2.Requests, i2.Errors)
	}
	sb.WriteString(`</tbody></table></body></html>`)
	return []byte(sb.String())
}

func htmlEsc(s string) string {
	s = strings.ReplaceAll(s, "&", "&amp;")
	s = strings.ReplaceAll(s, "<", "&lt;")
	s = strings.ReplaceAll(s, ">", "&gt;")
	return s
}

func htmlFmtBytes(b int64) string {
	switch {
	case b >= 1e9: return fmt.Sprintf("%.1f GB", float64(b)/1e9)
	case b >= 1e6: return fmt.Sprintf("%.1f MB", float64(b)/1e6)
	case b >= 1e3: return fmt.Sprintf("%.1f KB", float64(b)/1e3)
	default:       return fmt.Sprintf("%d B", b)
	}
}
