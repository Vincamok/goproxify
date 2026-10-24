// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"sort"
	"strings"
)

// IPCount : le trafic d'une IP sur la période, additionné sur toutes les passerelles. La carte et la répartition par
// pays se calculent à partir de ces comptes (ADR 0012) : chaque passerelle énumère ses IP, l'Admin fait l'union, puis
// regroupe par pays ou par ville avec son cache de géolocalisation.
type IPCount struct {
	IP       string
	Requests int64
	Errors   int64
}

type geoRow struct {
	cc, cn, city, region string
	lat, lon             float64
	located              bool // lat/lon connus et non nuls
}

// lookupGeo lit le cache de géolocalisation des IP demandées ; une IP absente du cache n'a pas d'entrée.
func lookupGeo(ctx context.Context, db *sql.DB, ips []string) (map[string]geoRow, error) {
	out := make(map[string]geoRow, len(ips))
	const chunk = 500
	for start := 0; start < len(ips); start += chunk {
		part := ips[start:min(start+chunk, len(ips))]
		args := make([]any, len(part))
		for i, ip := range part {
			args[i] = ip
		}
		rows, err := db.QueryContext(ctx, `SELECT ip, COALESCE(country_code,'?'), COALESCE(country_name,'Unknown'),
			COALESCE(city,''), COALESCE(region,''), lat, lon FROM geoip_cache WHERE ip IN (?`+strings.Repeat(",?", len(part)-1)+`)`, args...)
		if err != nil {
			return nil, err
		}
		for rows.Next() {
			var ip string
			var g geoRow
			var lat, lon sql.NullFloat64
			if err := rows.Scan(&ip, &g.cc, &g.cn, &g.city, &g.region, &lat, &lon); err != nil {
				rows.Close()
				return nil, err
			}
			g.lat, g.lon = lat.Float64, lon.Float64
			g.located = lat.Valid && (g.lat != 0 || g.lon != 0)
			out[ip] = g
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			return nil, err
		}
	}
	return out, nil
}

func ipsOf(counts []IPCount) []string {
	out := make([]string, len(counts))
	for i, c := range counts {
		out[i] = c.IP
	}
	return out
}

// GeoBreakdownFromIPs répartit le trafic par pays, comme GetGeoBreakdown le fait sur les lignes.
func GeoBreakdownFromIPs(ctx context.Context, db *sql.DB, counts []IPCount) []GeoEntry {
	geo, err := lookupGeo(ctx, db, ipsOf(counts))
	if err != nil {
		return nil
	}
	type key struct{ cc, cn string }
	agg := map[key]*GeoEntry{}
	for _, c := range counts {
		g, ok := geo[c.IP]
		if !ok {
			g = geoRow{cc: "?", cn: "Unknown"}
		}
		k := key{g.cc, g.cn}
		e := agg[k]
		if e == nil {
			e = &GeoEntry{CountryCode: g.cc, CountryName: g.cn}
			agg[k] = e
		}
		e.Requests += c.Requests
		e.Errors += c.Errors
	}
	out := make([]GeoEntry, 0, len(agg))
	for _, e := range agg {
		out = append(out, *e)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].CountryCode < out[j].CountryCode
	})
	if len(out) > 50 {
		out = out[:50]
	}
	var total int64
	for i := range out {
		if out[i].Requests > 0 {
			out[i].ErrorRate = float64(out[i].Errors) / float64(out[i].Requests) * 100
		}
		total += out[i].Requests
	}
	bans := geoBannedIPs(db)
	for i := range out {
		if total > 0 {
			out[i].Pct = float64(out[i].Requests) / float64(total) * 100
		}
		out[i].BannedIPs = bans[out[i].CountryCode]
	}
	return out
}

// GeoPointsFromIPs agrège le trafic par ville, comme GetGeoPoints le fait sur les lignes : les IP sans position sont
// ignorées, la position d'une ville est la moyenne de celles de ses IP pondérée par leurs requêtes.
func GeoPointsFromIPs(ctx context.Context, db *sql.DB, counts []IPCount, limit int) []GeoPoint {
	if limit <= 0 || limit > 1000 {
		limit = 300
	}
	geo, err := lookupGeo(ctx, db, ipsOf(counts))
	if err != nil {
		return nil
	}
	banned := activeBannedIPSet(db)
	type key struct{ cc, region, city string }
	type acc struct {
		pt         GeoPoint
		latW, lonW float64
	}
	agg := map[key]*acc{}
	for _, c := range counts {
		g, ok := geo[c.IP]
		if !ok || !g.located {
			continue
		}
		k := key{g.cc, g.region, g.city}
		a := agg[k]
		if a == nil {
			a = &acc{pt: GeoPoint{City: g.city, Region: g.region, CountryCode: g.cc, CountryName: g.cn}}
			agg[k] = a
		}
		w := float64(c.Requests)
		a.latW += g.lat * w
		a.lonW += g.lon * w
		a.pt.Requests += c.Requests
		a.pt.Errors += c.Errors
		a.pt.IPs++
		if banned[c.IP] {
			a.pt.BannedIPs++
		}
	}
	out := make([]GeoPoint, 0, len(agg))
	for _, a := range agg {
		pt := a.pt
		if pt.Requests > 0 {
			pt.Lat, pt.Lon = a.latW/float64(pt.Requests), a.lonW/float64(pt.Requests)
			pt.ErrorRate = float64(pt.Errors) / float64(pt.Requests) * 100
		}
		out = append(out, pt)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Requests != out[j].Requests {
			return out[i].Requests > out[j].Requests
		}
		return out[i].City < out[j].City
	})
	if len(out) > limit {
		out = out[:limit]
	}
	return out
}

// LiveLine est un accès récent tel que le rend une passerelle.
type LiveLine struct {
	IP     string
	Status int
	Domain string
	Ts     string
}

// LiveEventsFromLines complète des accès récents avec le pays, la ville et l'état de ban de leur IP, comme
// GetLiveIPs le fait sur les lignes.
func LiveEventsFromLines(ctx context.Context, db *sql.DB, lines []LiveLine) []LiveIPEvent {
	ips := make([]string, 0, len(lines))
	seen := map[string]bool{}
	for _, l := range lines {
		if !seen[l.IP] {
			seen[l.IP] = true
			ips = append(ips, l.IP)
		}
	}
	geo, _ := lookupGeo(ctx, db, ips)
	banned := activeBannedIPSet(db)
	var out []LiveIPEvent
	for _, l := range lines {
		g, ok := geo[l.IP]
		if !ok {
			g = geoRow{cc: "?", cn: "Unknown"}
		}
		ev := LiveIPEvent{IP: l.IP, CountryCode: g.cc, CountryName: g.cn, Status: l.Status, Domain: l.Domain, Ts: l.Ts, City: g.city, Lat: g.lat, Lon: g.lon}
		switch {
		case banned[l.IP]:
			ev.Kind = "banned"
		case l.Status >= 400:
			ev.Kind = "error"
		default:
			ev.Kind = "visit"
		}
		out = append(out, ev)
	}
	return out
}
