// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"context"
	"errors"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// maxIPLines borne les lignes lues pour un dossier : un scanner peut envoyer des millions de requêtes.
const maxIPLines = 50_000

// EdgeTraffic lit les logs par les mêmes passerelles que Prism et le traçage d'IP.
type EdgeTraffic struct{ Source *prismedge.Source }

// ErrDegraded : des passerelles n'ont pas répondu ou pas fini ; leurs lignes manquent, un dossier ou une mesure bâtis dessus seraient faux.
var ErrDegraded = errors.New("passerelles injoignables ou lecture partielle")

func (t EdgeTraffic) Lines(ctx context.Context, ip string, from, to time.Time) ([]Line, error) {
	lp := logapi.Params{IP: ip, Kind: "access",
		DateFrom: from.UTC().Format(time.RFC3339), DateTo: to.UTC().Format(time.RFC3339Nano)}
	lines, _, meta, err := t.Source.Lines(ctx, lp, "", maxIPLines)
	if errors.Is(err, prismedge.ErrNoGateway) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if meta.Degraded() {
		return nil, ErrDegraded
	}
	out := make([]Line, 0, len(lines))
	for _, l := range lines {
		if l.Status == 0 {
			continue
		}
		ts, err := time.Parse(time.RFC3339Nano, l.Ts)
		if err != nil {
			continue
		}
		out = append(out, Line{Ts: ts, Domain: l.Domain, Method: l.Method, Path: l.Path, Status: l.Status, WAF: l.WAFMatches, Signal: l.ThreatSignal})
	}
	return out, nil
}

func (t EdgeTraffic) PathReach(ctx context.Context, prefix string, from, to time.Time) (Reach, error) {
	it, found, meta, err := t.Source.Totals(ctx, analytics.Params{Path: prefix, From: from, To: to})
	if err != nil {
		return Reach{}, err
	}
	if meta.Degraded() {
		return Reach{}, ErrDegraded
	}
	if !found {
		return Reach{}, nil
	}
	return Reach{Requests: it.Requests, OK: it.Ok}, nil
}

// TotalRequests lit les cumuls par minute que les passerelles envoient à l'Admin (logs_minute, conservés 400 jours) : le
// total de 30 jours sans filtre n'a pas besoin de relire les lignes d'accès (près de 5 s pour 1,5 million de lignes, contre
// quelques millisecondes ici). Sans base, repli sur les passerelles.
func (t EdgeTraffic) TotalRequests(ctx context.Context, from, to time.Time) (int64, error) {
	if t.Source != nil && t.Source.DB != nil {
		var n int64
		err := t.Source.DB.QueryRowContext(ctx,
			`SELECT COALESCE(SUM(requests), 0) FROM logs_minute WHERE minute >= ? AND minute <= ?`,
			logs.MinuteKey(from), logs.MinuteKey(to)).Scan(&n)
		return n, err
	}
	it, found, meta, err := t.Source.Totals(ctx, analytics.Params{From: from, To: to})
	if err != nil {
		return 0, err
	}
	if meta.Degraded() {
		return 0, ErrDegraded
	}
	if !found {
		return 0, nil
	}
	return it.Requests, nil
}
