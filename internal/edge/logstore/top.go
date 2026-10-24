// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"errors"
	"sort"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/ipsketch"
)

// Regroupements pour l'Admin (ADR 0012, P1) : les valeurs les plus fréquentes d'un champ des accès, avec des
// compteurs que l'Admin peut additionner d'une passerelle à l'autre. Les trois modes sont ceux de l'algorithme de seuil
// (TPUT) qui rend les classements exacts : les meilleures valeurs, toutes les valeurs au-dessus d'un seuil, puis les
// comptes exacts d'une liste de valeurs.

// TopMode choisit ce que renvoie Top.
type TopMode string

const (
	// TopBest : les K valeurs les plus fréquentes.
	TopBest TopMode = "best"
	// TopAbove : toutes les valeurs vues au moins Min fois.
	TopAbove TopMode = "above"
	// TopExact : les comptes des valeurs demandées (absentes = 0).
	TopExact TopMode = "exact"
)

// Plafonds : un regroupement ne doit pas faire exploser la mémoire d'une passerelle.
const (
	maxTopGroups = 1_000_000 // valeurs distinctes retenues pendant le calcul
	// MaxTopAbove borne le nombre de valeurs rendues en mode TopAbove ; au-delà, le résultat est marqué partiel.
	MaxTopAbove = 200_000
	// MaxTopValues borne la liste d'une demande TopExact.
	MaxTopValues = 5_000
)

type topDim struct {
	expr string
	// nonEmpty : les lignes où le champ est vide ne comptent pas (référents, empreintes TLS).
	nonEmpty bool
}

var topDims = map[string]topDim{
	"path":      {expr: "path"},
	"ip":        {expr: "ip"},
	"component": {expr: "component"},
	"referrer":  {expr: "referrer", nonEmpty: true},
	"tls_ja4":   {expr: "tls_ja4", nonEmpty: true},
	"domain":    {expr: "domain"},
	"status":    {expr: "CAST(status AS TEXT)"},
	// minute : une valeur par minute (UTC), pour la courbe d'une sélection (AAAA-MM-JJTHH:MM).
	"minute": {expr: "substr(ts, 1, 16)"},
	// all : un seul groupe, les totaux de la sélection.
	"all": {expr: "'*'"},
}

// TopDimension dit si le champ peut servir de dimension.
func TopDimension(dim string) bool { _, ok := topDims[dim]; return ok }

// TopRequest décrit un regroupement.
type TopRequest struct {
	Dim    string
	Mode   TopMode
	K      int      // TopBest
	Min    int64    // TopAbove
	Values []string // TopExact
	// WithIPs : pour TopExact, joint à chaque valeur le résumé de ses IP attribuables (ni tronquées ni pseudonymisées).
	WithIPs bool
}

// TopItem additionne les accès d'une valeur du champ.
type TopItem struct {
	Value      string
	Requests   int64
	Errors     int64 // statut >= 400
	Bytes      int64
	LatencySum int64 // somme des latences, pour la moyenne
	Flagged    int64 // signalées par le WAF ou Ephor
	// Blocked : refusées (403, 429) ou signalées ; Ok : réussies (< 400) et non bloquées.
	Blocked, Ok         int64
	Bots                int64  // robots, au sens de la colonne bots des cumuls (voir isBot)
	FirstSeen, LastSeen string // plus ancien et plus récent horodatage, au format fixe de la base
	Truncated           bool   // au moins une ligne à IP tronquée
	JA3                 string
	IPs                 *ipsketch.Summary
}

// TopResult est la réponse d'une passerelle.
type TopResult struct {
	Items []TopItem
	// Complete : en mode TopBest, Items contient toutes les valeurs de la passerelle (moins de K).
	Complete bool
	// Partial : le délai est écoulé ou la limite de mémoire atteinte avant la fin de la période.
	Partial bool
}

func sortTop(items []TopItem) {
	sort.Slice(items, func(i, j int) bool {
		if items[i].Requests != items[j].Requests {
			return items[i].Requests > items[j].Requests
		}
		return items[i].Value < items[j].Value
	})
}

// Top calcule un regroupement sur les accès de la période demandée (Query.Kinds est ignoré : les accès seulement).
func (s *Store) Top(ctx context.Context, q Query, r TopRequest) (TopResult, error) {
	dim, ok := topDims[r.Dim]
	if !ok {
		return TopResult{}, errors.New("logstore: dimension inconnue")
	}
	if r.Mode == TopExact && len(r.Values) > MaxTopValues {
		return TopResult{}, errors.New("logstore: trop de valeurs demandées")
	}
	q.Kinds = []Kind{KindAccess}
	where, args := s.where(q)
	conds := []string{"status > 0"}
	if dim.nonEmpty {
		conds = append(conds, dim.expr+" != ''")
	}
	var condArgs []any
	if r.Mode == TopExact {
		if len(r.Values) == 0 {
			return TopResult{Complete: true}, nil
		}
		conds = append(conds, dim.expr+" IN (?"+strings.Repeat(",?", len(r.Values)-1)+")")
		for _, v := range r.Values {
			condArgs = append(condArgs, v)
		}
	}
	if where == "" {
		where = " WHERE " + strings.Join(conds, " AND ")
	} else {
		where += " AND " + strings.Join(conds, " AND ")
	}
	args = append(args, condArgs...)

	files := s.files(KindAccess)
	var inPlay []periodFile
	for i := len(files) - 1; i >= 0; i-- {
		f := files[i]
		if q.newerThan(f) {
			continue
		}
		if q.olderThan(f, KindAccess) {
			break
		}
		inPlay = append(inPlay, f)
	}
	// Une seule période : SQLite classe et coupe lui-même. Plusieurs : un même nom peut s'étendre sur plusieurs
	// fichiers, il faut additionner avant de classer.
	tail, tailArgs := "", []any(nil)
	if len(inPlay) == 1 {
		switch r.Mode {
		case TopBest:
			tail, tailArgs = " ORDER BY 2 DESC, 1 ASC LIMIT ?", []any{max(r.K, 1) + 1}
		case TopAbove:
			tail, tailArgs = " HAVING COUNT(*) >= ?", []any{r.Min}
		}
	}

	groups := map[string]*TopItem{}
	var sets map[string]*ipsketch.Set
	if r.Mode == TopExact && r.WithIPs {
		sets = map[string]*ipsketch.Set{}
	}
	partial := false
	for _, f := range inPlay {
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			return TopResult{}, err
		}
		rows, err := db.QueryContext(ctx, `SELECT `+dim.expr+`, COUNT(*), COALESCE(SUM(CASE WHEN status >= 400 THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(bytes), 0), COALESCE(SUM(latency_ms), 0), COALESCE(MAX(ip_truncated), 0),
			COALESCE(SUM(CASE WHEN threat_signal != '' OR waf_matches != '' THEN 1 ELSE 0 END), 0), COALESCE(MAX(tls_ja3), ''),
			COALESCE(SUM(CASE WHEN status IN (403, 429) OR threat_signal != '' OR waf_matches != '' THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status < 400 AND status NOT IN (403, 429) AND threat_signal = '' AND waf_matches = '' THEN 1 ELSE 0 END), 0),
			MIN(ts), MAX(ts),
			COALESCE(SUM(CASE WHEN lower(user_agent) LIKE '%bot%' OR lower(referrer) LIKE '%bot%' OR lower(path) LIKE '%bot%' THEN 1 ELSE 0 END), 0)
			FROM entries`+where+` GROUP BY 1`+tail, append(append([]any(nil), args...), tailArgs...)...)
		if err != nil {
			if ctx.Err() != nil {
				partial = true
				break
			}
			return TopResult{}, err
		}
		for rows.Next() {
			var it TopItem
			var trunc int
			if err := rows.Scan(&it.Value, &it.Requests, &it.Errors, &it.Bytes, &it.LatencySum, &trunc, &it.Flagged, &it.JA3, &it.Blocked, &it.Ok, &it.FirstSeen, &it.LastSeen, &it.Bots); err != nil {
				rows.Close()
				return TopResult{}, err
			}
			it.Truncated = trunc != 0
			g := groups[it.Value]
			if g == nil {
				if len(groups) >= maxTopGroups {
					partial = true
					continue
				}
				c := it
				groups[it.Value] = &c
				continue
			}
			g.Requests += it.Requests
			g.Errors += it.Errors
			g.Bytes += it.Bytes
			g.LatencySum += it.LatencySum
			g.Flagged += it.Flagged
			g.Blocked += it.Blocked
			g.Ok += it.Ok
			g.Bots += it.Bots
			if it.FirstSeen < g.FirstSeen {
				g.FirstSeen = it.FirstSeen
			}
			if it.LastSeen > g.LastSeen {
				g.LastSeen = it.LastSeen
			}
			g.Truncated = g.Truncated || it.Truncated
			if it.JA3 > g.JA3 {
				g.JA3 = it.JA3
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			if ctx.Err() != nil {
				partial = true
				break
			}
			return TopResult{}, err
		}
		if sets != nil {
			ipRows, err := db.QueryContext(ctx, `SELECT `+dim.expr+`, ip FROM entries`+where+` AND ip_truncated = 0 AND ip != '' GROUP BY 1, 2`, args...)
			if err != nil {
				if ctx.Err() != nil {
					partial = true
					break
				}
				return TopResult{}, err
			}
			for ipRows.Next() {
				var v, ip string
				if ipRows.Scan(&v, &ip) != nil {
					continue
				}
				if sets[v] == nil {
					sets[v] = ipsketch.New()
				}
				sets[v].Add(ip)
			}
			err = ipRows.Err()
			ipRows.Close()
			if err != nil {
				if ctx.Err() != nil {
					partial = true
					break
				}
				return TopResult{}, err
			}
		}
	}

	items := make([]TopItem, 0, len(groups))
	for _, g := range groups {
		if sets != nil {
			set := sets[g.Value]
			if set == nil {
				set = ipsketch.New()
			}
			sum := set.Summary()
			g.IPs = &sum
		}
		items = append(items, *g)
	}
	sortTop(items)
	res := TopResult{Partial: partial}
	switch r.Mode {
	case TopBest:
		k := max(r.K, 1)
		res.Complete = len(items) <= k && !partial
		if len(items) > k {
			items = items[:k]
		}
	case TopAbove:
		kept := items[:0]
		for _, it := range items {
			if it.Requests >= r.Min {
				kept = append(kept, it)
			}
		}
		items = kept
		if len(items) > MaxTopAbove {
			items, res.Partial = items[:MaxTopAbove], true
		}
	}
	res.Items = items
	return res, nil
}

// UniqueIPs résume l'ensemble des IP des accès de la période (celles qui ont servi au moins une requête).
func (s *Store) UniqueIPs(ctx context.Context, q Query) (ipsketch.Summary, bool, error) {
	q.Kinds = []Kind{KindAccess}
	where, args := s.where(q)
	if where == "" {
		where = " WHERE status > 0 AND ip != ''"
	} else {
		where += " AND status > 0 AND ip != ''"
	}
	set := ipsketch.New()
	for _, f := range s.files(KindAccess) {
		if q.newerThan(f) || q.olderThan(f, KindAccess) {
			continue
		}
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			return ipsketch.Summary{}, false, err
		}
		rows, err := db.QueryContext(ctx, `SELECT DISTINCT ip FROM entries`+where, args...)
		if err != nil {
			if ctx.Err() != nil {
				return set.Summary(), true, nil
			}
			return ipsketch.Summary{}, false, err
		}
		for rows.Next() {
			var ip string
			if rows.Scan(&ip) == nil {
				set.Add(ip)
			}
		}
		err = rows.Err()
		rows.Close()
		if err != nil {
			if ctx.Err() != nil {
				return set.Summary(), true, nil
			}
			return ipsketch.Summary{}, false, err
		}
	}
	return set.Summary(), false, nil
}

// RecentCounts compte les accès depuis since : le total, les refusés (403, 429) et les erreurs de backend (5xx).
func (s *Store) RecentCounts(ctx context.Context, since time.Time) (total, blocked, errors int64, err error) {
	q := Query{Kinds: []Kind{KindAccess}, From: since}
	where, args := s.where(q)
	where += " AND status > 0"
	for _, f := range s.files(KindAccess) {
		if q.olderThan(f, KindAccess) {
			continue
		}
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			return 0, 0, 0, err
		}
		var t, b, e int64
		if err := db.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(CASE WHEN status IN (403, 429) THEN 1 ELSE 0 END), 0),
			COALESCE(SUM(CASE WHEN status >= 500 THEN 1 ELSE 0 END), 0) FROM entries`+where, args...).Scan(&t, &b, &e); err != nil {
			return 0, 0, 0, err
		}
		total, blocked, errors = total+t, blocked+b, errors+e
	}
	return total, blocked, errors, nil
}
