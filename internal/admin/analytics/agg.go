// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/logs"
)

// aggTotals : mêmes cumuls que rawKPIs, lus dans logs_minute.
func aggTotals(ctx context.Context, db *sql.DB, p Params) (reqs, bw, errs, bots int64, avgLat float64, err error) {
	w, args := aggWhere(p)
	var latSum int64
	err = db.QueryRowContext(ctx,
		`SELECT COALESCE(SUM(requests),0), COALESCE(SUM(bytes),0), COALESCE(SUM(latency_ms_sum),0),
		        COALESCE(SUM(CASE WHEN status >= 400 THEN requests ELSE 0 END),0), COALESCE(SUM(bots),0)
		 FROM logs_minute `+w, args...).Scan(&reqs, &bw, &latSum, &errs, &bots)
	if err == nil && reqs > 0 {
		avgLat = float64(latSum) / float64(reqs)
	}
	return
}

// aggTimeline : mêmes points que GetTimeline, regroupés depuis les minutes (heure locale du serveur).
func aggTimeline(ctx context.Context, db *sql.DB, p Params, tfmt string) ([]TimePoint, error) {
	w, args := aggWhere(p)
	rows, err := db.QueryContext(ctx,
		`SELECT strftime('`+tfmt+`', minute || ':00Z', 'localtime') AS b, SUM(requests),
		        SUM(CASE WHEN status >= 400 THEN requests ELSE 0 END), SUM(bytes)
		 FROM logs_minute `+w+` GROUP BY b ORDER BY b`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []TimePoint
	for rows.Next() {
		var tp TimePoint
		if err := rows.Scan(&tp.Bucket, &tp.Requests, &tp.Errors, &tp.Bytes); err != nil {
			return nil, err
		}
		out = append(out, tp)
	}
	return out, rows.Err()
}

// aggStatusCounts : requêtes par code HTTP, lues dans logs_minute.
func aggStatusCounts(ctx context.Context, db *sql.DB, p Params) (*sql.Rows, error) {
	w, args := aggWhere(p)
	return db.QueryContext(ctx, `SELECT status, SUM(requests) FROM logs_minute `+w+` GROUP BY status ORDER BY status`, args...)
}

// aggBackendErrors : mêmes chiffres que GetBackendErrors, lus dans logs_minute (jointure sur le domaine du proxy).
func aggBackendErrors(ctx context.Context, db *sql.DB, p Params) ([]BackendError, error) {
	args := []any{logs.MinuteKey(p.From), logs.MinuteKey(p.To)}
	nodeJoin := ""
	if p.NodeName != "" {
		nodeJoin = " AND l.node_name = ?"
		args = append(args, p.NodeName)
	}
	proxyFilter := ""
	if c, a := domainCond("json_extract(p.config,'$.host')", p.Proxy); c != "" {
		proxyFilter = " AND " + c
		args = append(args, a...)
	}
	rows, err := db.QueryContext(ctx,
		`SELECT
		   p.name,
		   json_extract(p.config,'$.host') AS domain,
		   json_extract(p.config,'$.backend') AS backend_url,
		   COALESCE(SUM(l.requests), 0) AS total,
		   COALESCE(SUM(CASE WHEN l.status>=400 THEN l.requests ELSE 0 END), 0) AS errors,
		   ROUND(100.0*SUM(CASE WHEN l.status>=400 THEN l.requests ELSE 0 END)/NULLIF(SUM(l.requests),0),1) AS error_rate,
		   ROUND(1.0*SUM(l.latency_ms_sum)/NULLIF(SUM(l.requests),0),0) AS avg_lat_ms
		 FROM proxies p
		 LEFT JOIN logs_minute l ON l.domain = json_extract(p.config,'$.host')
		                 AND l.minute >= ?
		                 AND l.minute <= ?`+nodeJoin+`
		 WHERE p.enabled=1`+proxyFilter+`
		 GROUP BY p.id
		 HAVING COALESCE(SUM(l.requests), 0) > 0
		 ORDER BY error_rate DESC, total DESC
		 LIMIT 20`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []BackendError{}
	for rows.Next() {
		var r BackendError
		var backendURL, domain *string
		var errRate, avgLat sql.NullFloat64
		if rows.Scan(&r.Name, &domain, &backendURL, &r.Total, &r.Errors, &errRate, &avgLat) != nil {
			continue
		}
		if domain != nil {
			r.Domain = *domain
		}
		if backendURL != nil {
			r.BackendURL = *backendURL
		}
		if errRate.Valid {
			r.ErrorRate = errRate.Float64
		}
		if avgLat.Valid {
			r.AvgLatMs = avgLat.Float64
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// aggWhere : la fenêtre est arrondie à la minute, au plus 59 s de trafic en plus de chaque côté. Une borne absente ne
// limite pas.
func aggWhere(p Params) (string, []any) {
	var conds []string
	var args []any
	if !p.From.IsZero() {
		conds = append(conds, "minute >= ?")
		args = append(args, logs.MinuteKey(p.From))
	}
	if !p.To.IsZero() {
		conds = append(conds, "minute <= ?")
		args = append(args, logs.MinuteKey(p.To))
	}
	if c, a := domainCond("domain", p.Proxy); c != "" {
		conds = append(conds, c)
		args = append(args, a...)
	}
	if p.NodeName != "" {
		conds = append(conds, "node_name = ?")
		args = append(args, p.NodeName)
	}
	if len(conds) == 0 {
		return "", nil
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

// Les chiffres globaux de Prism (KPIs, courbe, codes HTTP, SLO, erreurs par backend) se lisent dans les cumuls par minute
// que les passerelles calculent à la source (ADR 0012). Ils ne portent ni IP ni chemin : une sélection filtrée sur l'un
// d'eux est calculée par les passerelles (voir le paquet prismedge) et n'a pas de sens ici.

// GetTotals retourne les totaux de la période.
func GetTotals(db *sql.DB, p Params) Totals {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	reqs, bw, errs, bots, avgLat, err := aggTotals(ctx, db, p)
	if err != nil {
		return Totals{}
	}
	return Totals{Requests: reqs, Bytes: bw, Errors: errs, Bots: bots, AvgLatencyMs: avgLat}
}

// GetKPIs retourne les KPIs de la période et leur écart avec la période précédente. Les IP uniques ne sont pas dans les
// cumuls : l'appelant les demande aux passerelles.
func GetKPIs(db *sql.DB, p Params) KPIs {
	return BuildKPIs(GetTotals(db, p), GetTotals(db, PreviousPeriod(p, true)), 0)
}

// GetTimeline retourne les requêtes par tranche de temps (heure locale du serveur) : bucket vaut "minute", "hour" ou "day".
func GetTimeline(db *sql.DB, p Params, bucket string) []TimePoint {
	tfmt := "%Y-%m-%dT%H:00"
	switch bucket {
	case "minute":
		tfmt = "%Y-%m-%dT%H:%M"
	case "day":
		tfmt = "%Y-%m-%d"
	}
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	out, err := aggTimeline(ctx, db, p, tfmt)
	if err != nil {
		return nil
	}
	return out
}

// GetStatusGroups retourne la répartition par famille de codes HTTP.
func GetStatusGroups(db *sql.DB, p Params) []StatusGroup {
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	rows, err := aggStatusCounts(ctx, db, p)
	if err != nil {
		return nil
	}
	defer rows.Close()
	counts := map[int]int64{}
	for rows.Next() {
		var code int
		var cnt int64
		rows.Scan(&code, &cnt) //nolint:errcheck
		counts[code] += cnt
	}
	return StatusGroupsFromCounts(counts)
}
