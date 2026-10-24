// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"math"
	"sort"
	"time"
)

// BackendError taux d'erreurs d'un proxy (et de son backend) sur la période.
type BackendError struct {
	Name       string  `json:"name"`
	Domain     string  `json:"domain"`
	BackendURL string  `json:"backend_url"`
	Total      int64   `json:"total"`
	Errors     int64   `json:"errors"`
	ErrorRate  float64 `json:"error_rate"`
	AvgLatMs   float64 `json:"avg_lat_ms"`
}

// Anomaly écart notable détecté sur la période. Le texte affiché est construit côté UI
// (traduit) à partir de Kind et des valeurs.
type Anomaly struct {
	Kind     string  `json:"kind"`     // error_spike | dominant_ip | country_errors | backend_errors | bot_share
	Level    string  `json:"level"`    // critical | warning
	Subject  string  `json:"subject"`  // bucket, IP, code pays ou domaine
	Label    string  `json:"label"`    // nom lisible (pays, backend)
	Value    float64 `json:"value"`    // valeur mesurée (erreurs, part %, taux %)
	Baseline float64 `json:"baseline"` // valeur habituelle (moyenne) quand elle a un sens
	Count    int64   `json:"count"`    // volume de requêtes concerné
	Banned   bool    `json:"banned,omitempty"`
}

// GetBackendErrors retourne les 20 proxys actifs les plus en erreur sur la période, d'après les cumuls par minute.
func GetBackendErrors(ctx context.Context, db *sql.DB, p Params) ([]BackendError, error) {
	return aggBackendErrors(ctx, db, p)
}

// Remote fournit les règles qui portent sur les lignes d'accès (IP dominante, pays en erreur, sélection par IP ou par
// chemin) : elles vivent dans les bases de logs des passerelles (ADR 0012). Une règle dont la source échoue est ignorée.
type Remote interface {
	Available(ctx context.Context, p Params) bool
	TopAttributableIP(ctx context.Context, p Params) (IPEntry, bool, error)
	GeoBreakdown(ctx context.Context, p Params) ([]GeoEntry, error)
	// FilteredTimeline et FilteredTotals servent une sélection par IP ou par chemin, que les cumuls par minute ne portent pas.
	FilteredTimeline(ctx context.Context, p Params, bucket string) ([]TimePoint, error)
	FilteredTotals(ctx context.Context, p Params) (Totals, error)
}

// DetectAnomalies applique des règles simples sur la période (pas de modèle appris). Résultat trié : critiques
// d'abord, puis par ordre de détection. remote est la source des règles qui portent sur des lignes ; nil (aucune
// passerelle), elles ne sont pas évaluées.
func DetectAnomalies(ctx context.Context, db *sql.DB, p Params, remote Remote) []Anomaly {
	useRemote := remote != nil && remote.Available(ctx, p)
	out := []Anomaly{}

	// Pic d'erreurs : point de la courbe > moyenne + 2,5 écarts-types (au moins 10 erreurs).
	bucket := "hour"
	if p.To.Sub(p.From) <= 6*time.Hour {
		bucket = "minute"
	}
	filtered := p.IP != "" || p.Path != ""
	var tl []TimePoint
	switch {
	case !filtered:
		tl = GetTimeline(db, p, bucket)
	case useRemote:
		tl, _ = remote.FilteredTimeline(ctx, p, bucket)
	}
	if len(tl) >= 4 {
		var sum float64
		for _, pt := range tl {
			sum += float64(pt.Errors)
		}
		mean := sum / float64(len(tl))
		var sq float64
		for _, pt := range tl {
			sq += math.Pow(float64(pt.Errors)-mean, 2)
		}
		sd := math.Sqrt(sq / float64(len(tl)))
		peak := tl[0]
		for _, pt := range tl {
			if pt.Errors > peak.Errors {
				peak = pt
			}
		}
		if peak.Errors >= 10 && float64(peak.Errors) > mean+2.5*sd {
			out = append(out, Anomaly{Kind: "error_spike", Level: "critical", Subject: peak.Bucket,
				Value: float64(peak.Errors), Baseline: mean, Count: peak.Requests})
		}
	}

	var totals Totals
	switch {
	case !filtered:
		totals = GetTotals(db, p)
	case useRemote:
		totals, _ = remote.FilteredTotals(ctx, p)
	}
	reqs, bots := totals.Requests, totals.Bots

	// IP dominante : ≥ 20 % des requêtes de la période (et au moins 50). Une IP tronquée ou
	// pseudonymisée regroupe plusieurs clients : l'anomalie et son action Bannir ne la visent pas.
	var ips []IPEntry
	if useRemote {
		if ip, ok, err := remote.TopAttributableIP(ctx, p); err == nil && ok {
			ips = []IPEntry{ip}
		}
	}
	if len(ips) == 1 && reqs > 0 {
		if share := float64(ips[0].Requests) / float64(reqs); share >= 0.2 && ips[0].Requests >= 50 {
			out = append(out, Anomaly{Kind: "dominant_ip", Level: "warning", Subject: ips[0].IP,
				Value: share * 100, Count: ips[0].Requests, Banned: activeBannedIPSet(db)[ips[0].IP]})
		}
	}

	// Pays en erreur : ≥ 20 % d'erreurs sur au moins 50 requêtes (2 maximum).
	n := 0
	var geo []GeoEntry
	if useRemote {
		geo, _ = remote.GeoBreakdown(ctx, p)
	}
	for _, g := range geo {
		if g.Requests >= 50 && g.ErrorRate >= 20 && n < 2 {
			out = append(out, Anomaly{Kind: "country_errors", Level: "warning", Subject: g.CountryCode,
				Label: g.CountryName, Value: g.ErrorRate, Count: g.Requests})
			n++
		}
	}

	// Backends en difficulté : > 10 % d'erreurs sur au moins 20 requêtes (2 maximum).
	if rows, err := GetBackendErrors(ctx, db, p); err == nil {
		n = 0
		for _, r := range rows {
			if r.Total >= 20 && r.ErrorRate > 10 && n < 2 {
				out = append(out, Anomaly{Kind: "backend_errors", Level: "critical", Subject: r.Domain,
					Label: r.Name, Value: r.ErrorRate, Count: r.Total})
				n++
			}
		}
	}

	// Part de bots ≥ 30 %.
	if reqs > 0 {
		if share := float64(bots) / float64(reqs) * 100; share >= 30 {
			out = append(out, Anomaly{Kind: "bot_share", Level: "warning", Value: share, Count: bots})
		}
	}

	sort.SliceStable(out, func(i, j int) bool { return out[i].Level == "critical" && out[j].Level != "critical" })
	return out
}
