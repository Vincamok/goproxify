// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"fmt"
	"math"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// MetricDef décrit une métrique proposée aux conditions.
type MetricDef struct {
	Key   string `json:"key"`
	Label string `json:"label"`
	Unit  string `json:"unit,omitempty"`
	// Scope : sur quoi porte chaque série (global, host, edge, domain, stage).
	Scope string `json:"scope"`
	// Kind : gauge (valeur instantanée) ou counter (cumul : increase et rate ont un sens).
	Kind string `json:"kind"`
}

// MetricValue est l'agrégat d'une série sur la fenêtre.
type MetricValue struct {
	Entity  string
	Value   float64
	Samples int
}

// MetricSource fournit les séries récentes (automation/metrics.Store).
type MetricSource interface {
	Catalog() []MetricDef
	Entities(key string) []string
	Query(key, entity string, window time.Duration, agg string) []MetricValue
}

var aggregations = []modules.Option{
	{Value: "avg", Label: "Moyenne"}, {Value: "max", Label: "Maximum"}, {Value: "min", Label: "Minimum"},
	{Value: "last", Label: "Dernière valeur"}, {Value: "increase", Label: "Augmentation (compteur)"},
	{Value: "rate", Label: "Par seconde (compteur)"},
}

var operators = []modules.Option{
	{Value: ">", Label: ">"}, {Value: ">=", Label: "≥"}, {Value: "<", Label: "<"}, {Value: "<=", Label: "≤"},
	{Value: "==", Label: "="}, {Value: "!=", Label: "≠"},
}

func registerMetricCondition() {
	RegisterCondition(modules.Manifest{Type: "metric_threshold", Label: "Seuil sur une métrique",
		Attrs: attrs(false, "metrics", "metric", "entity", "value", "threshold", "window", "host", "proxy_id", "proxy_name"),
		Fields: []modules.Field{
			{Key: "metric", Label: "Métrique", Kind: modules.KindSelect, Source: "metrics", Required: true},
			{Key: "entity", Label: "Sur (vide = n'importe lequel)", Kind: modules.KindSelect, Source: "metric_entities",
				Help: "Proxy, passerelle ou domaine selon la métrique."},
			{Key: "aggregation", Label: "Agrégation", Kind: modules.KindSelect, Default: "avg", Options: aggregations},
			{Key: "window", Label: "Fenêtre (1 h au plus)", Kind: modules.KindDuration, Default: "5m"},
			{Key: "operator", Label: "Opérateur", Kind: modules.KindSelect, Default: ">", Options: operators},
			{Key: "value", Label: "Seuil", Kind: modules.KindNumber, Required: true},
			{Key: "min_samples", Label: "Points minimum", Kind: modules.KindNumber, Default: 3,
				Help: "Sans assez de points (trafic nul, Admin tout juste démarré), la condition reste fausse."},
		}}, evalMetricThreshold, func(cfg map[string]any) error {
		if d, _, err := cfgDur(cfg, "window", "5m"); err == nil && d > time.Hour {
			return fmt.Errorf("window : 1 h au plus (l'historique des métriques est d'une heure)")
		}
		return nil
	})
}

func compare(op string, v, threshold float64) bool {
	switch op {
	case ">=":
		return v >= threshold
	case "<":
		return v < threshold
	case "<=":
		return v <= threshold
	case "==":
		return v == threshold
	case "!=":
		return v != threshold
	}
	return v > threshold
}

func evalMetricThreshold(ctx context.Context, s *Service, cfg map[string]any) (bool, map[string]any, error) {
	if s.deps.Metrics == nil {
		return false, nil, nil
	}
	key := cfgStr(cfg, "metric")
	var def *MetricDef
	for _, d := range s.deps.Metrics.Catalog() {
		if d.Key == key {
			d := d
			def = &d
		}
	}
	if def == nil {
		return false, nil, fmt.Errorf("métrique inconnue : %q", key)
	}
	window, windowRaw, err := cfgDur(cfg, "window", "5m")
	if err != nil {
		return false, nil, err
	}
	agg := cfgStr(cfg, "aggregation")
	if agg == "" {
		agg = "avg"
	}
	op := cfgStr(cfg, "operator")
	threshold, ok := cfg["value"].(float64)
	if !ok {
		return false, nil, fmt.Errorf("value : seuil numérique requis")
	}
	minSamples := cfgInt(cfg, "min_samples", 3)
	var best *MetricValue
	for _, v := range s.deps.Metrics.Query(key, cfgStr(cfg, "entity"), window, agg) {
		v := v
		if v.Samples < minSamples || math.IsNaN(v.Value) || !compare(op, v.Value, threshold) {
			continue
		}
		// La série la plus éloignée du seuil est la plus parlante (la pire).
		if best == nil || math.Abs(v.Value-threshold) > math.Abs(best.Value-threshold) {
			best = &v
		}
	}
	if best == nil {
		return false, nil, nil
	}
	detail := map[string]any{"metric": key, "entity": best.Entity, "value": best.Value, "threshold": threshold,
		"window": windowRaw, "aggregation": agg}
	switch def.Scope {
	case "host":
		detail["host"] = best.Entity
		var id, name string
		if s.db.QueryRowContext(ctx, `SELECT id, name FROM proxies WHERE json_extract(config,'$.domain')=? LIMIT 1`, best.Entity).Scan(&id, &name) == nil {
			detail["proxy_id"], detail["proxy_name"] = id, name
		}
	case "edge":
		detail["node_name"] = best.Entity
	case "domain":
		detail["domain"] = best.Entity
	}
	return true, detail, nil
}
