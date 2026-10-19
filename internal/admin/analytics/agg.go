// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"strings"
	"time"
)

// aggMinWindow : en dessous, les lignes brutes (bornées par l'index sur ts) coûtent moins cher que
// l'arrondi à la minute ne vaut. Au-dessus, le coût des lignes brutes suit le trafic.
const aggMinWindow = time.Hour

const aggMinuteLayout = "2006-01-02T15:04"

// aggUsable dit si une requête peut être servie par logs_minute : fenêtre bornée d'au moins une
// heure, aucun filtre que les agrégats ne portent pas (IP, chemin), et historique rattrapé.
func aggUsable(ctx context.Context, db *sql.DB, p Params) bool {
	if p.IP != "" || p.Path != "" || p.From.IsZero() || p.To.IsZero() || p.To.Sub(p.From) < aggMinWindow {
		return false
	}
	var ready int
	err := db.QueryRowContext(ctx, `SELECT COALESCE((SELECT v FROM logs_minute_state WHERE k='ready'), 0)`).Scan(&ready)
	return err == nil && ready == 1
}

// aggWhere : la fenêtre est arrondie à la minute, au plus 59 s de trafic en plus de chaque côté.
func aggWhere(p Params) (string, []any) {
	conds := []string{"minute >= ?", "minute <= ?"}
	args := []any{p.From.UTC().Format(aggMinuteLayout), p.To.UTC().Format(aggMinuteLayout)}
	if c, a := domainCond("domain", p.Proxy); c != "" {
		conds = append(conds, c)
		args = append(args, a...)
	}
	if p.NodeName != "" {
		conds = append(conds, "node_name = ?")
		args = append(args, p.NodeName)
	}
	return "WHERE " + strings.Join(conds, " AND "), args
}

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
