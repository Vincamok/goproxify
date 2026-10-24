// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// ipTraffic est le trafic d'une plage ou d'un ASN sur une période, par IP : de quoi dire ce qu'un ban couperait.
type ipTraffic struct {
	Requests, Blocked, OKRequests int
	IPHits, OKIPs                 map[string]int
	ScanLimited                   bool
	// Meta dit quelles passerelles manquent.
	Meta prismedge.Meta
	Edge bool
}

// readIPTraffic mesure le trafic des IP que match retient, depuis since, d'après les bases de logs des passerelles
// (ranges borne leur lecture). Sans passerelle il n'y a pas de trafic.
func readIPTraffic(ctx context.Context, edge *prismedge.Source, since time.Time, ranges [][2]string, match func(ip string) bool) (ipTraffic, error) {
	t := ipTraffic{IPHits: map[string]int{}, OKIPs: map[string]int{}}
	p := analytics.Params{From: since, To: time.Now()}
	if edge == nil || !edge.Available(ctx, p) {
		return t, nil
	}
	stats, meta, err := edge.IPStats(ctx, p, ranges)
	if err != nil {
		return ipTraffic{}, err
	}
	t.Meta, t.Edge, t.ScanLimited = meta, true, meta.Partial
	for _, s := range stats {
		if !match(s.IP) {
			continue
		}
		t.Requests += int(s.Requests)
		t.Blocked += int(s.Blocked)
		t.OKRequests += int(s.Ok)
		t.IPHits[s.IP] += int(s.Requests)
		if s.Ok > 0 {
			t.OKIPs[s.IP] += int(s.Ok)
		}
	}
	return t, nil
}

// missingGateways rend l'avertissement des passerelles dont le trafic manque, ou "".
func (t ipTraffic) missingGateways() string {
	if len(t.Meta.Unreachable) == 0 {
		return ""
	}
	names := make([]string, len(t.Meta.Unreachable))
	for i, u := range t.Meta.Unreachable {
		names[i] = u.NodeName
	}
	return fmt.Sprintf("passerelle(s) injoignable(s) : %s — leur trafic manque dans ces chiffres", strings.Join(names, ", "))
}

// traceLine est une ligne de log telle que la trace d'IP la consomme, qu'elle vienne de la copie de l'Admin ou d'une
// passerelle.
type traceLine struct {
	Ts, IP, Domain, Method, Path, Node, Signal, Component, Level, Message string
	Status                                                                int
	Matches                                                               []string
}

// traceEdgeMaxLines borne les lignes lues dans les passerelles pour une trace (les plus récentes d'abord).
const traceEdgeMaxLines = 400_000

// readTraceLinesFromEdges lit, dans les bases de logs des passerelles, les lignes de la cible sur la période, de la
// plus ancienne à la plus récente.
func readTraceLinesFromEdges(ctx context.Context, edge *prismedge.Source, qy TraceQuery, from, to time.Time) ([]traceLine, bool, prismedge.Meta, error) {
	lp := logapi.Params{DateFrom: from.UTC().Format(time.RFC3339), DateTo: to.UTC().Format(time.RFC3339Nano)}
	switch bounds := qy.matcher.sqlBounds; {
	case qy.matcher.scanAll:
	case len(bounds) > 0 && len(bounds) <= 400:
		parts := make([]string, len(bounds))
		for i, b := range bounds {
			parts[i] = b[0] + "|" + b[1]
		}
		lp.IPRanges = strings.Join(parts, ",")
	case len(bounds) > 0:
	case qy.Target.IsSingleIP():
		lp.IP = qy.Target.Addr().String()
	default:
		if lo, hi, ok := security.TraceIPRange(qy.Target); ok {
			lp.IPFrom, lp.IPTo = lo, hi
		}
	}
	lines, capped, meta, err := edge.Lines(ctx, lp, qy.Node, traceEdgeMaxLines)
	if err != nil {
		return nil, false, meta, err
	}
	sort.SliceStable(lines, func(i, j int) bool { return lines[i].Ts < lines[j].Ts })
	out := make([]traceLine, len(lines))
	for i, l := range lines {
		out[i] = traceLine{Ts: l.Ts, IP: l.IP, Domain: l.Domain, Method: l.Method, Path: l.Path, Node: l.Node, Signal: l.ThreatSignal,
			Component: l.Component, Level: l.Level, Message: l.Message, Status: l.Status, Matches: l.WAFMatches}
	}
	return out, capped, meta, nil
}
