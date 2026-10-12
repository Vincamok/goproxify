// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"fmt"
	"time"

	"github.com/vincamok/goproxify/internal/metricwindow"
)

// MetricScopes liste les métriques que chaque passerelle calcule sur son propre trafic, avec ce que désigne
// l'entité de chaque série. L'Admin n'envoie aux passerelles qu'un flux qui surveille l'une d'elles. Les
// débits par proxy et les totaux ne sont pas dans la liste : sur une passerelle seule ils ne vaudraient
// qu'une part du trafic, et un seuil réglé pour le cluster ne se déclencherait plus.
var MetricScopes = map[string]string{
	"proxy.error_rate_pct":   "host",
	"proxy.p95_ms":           "host",
	"edge.rps":               "edge",
	"edge.error_rate_pct":    "edge",
	"edge.p95_ms":            "edge",
	"tls.cert_expires_days":  "domain",
	"tls.handshake_p95_ms":   "host",
	"tls.active_connections": "host",
}

func (e *Engine) evalMetricThreshold(c Condition) (bool, map[string]any, error) {
	scope, ok := MetricScopes[c.Metric]
	if !ok {
		return false, nil, fmt.Errorf("métrique %q non calculée par la passerelle", c.Metric)
	}
	if c.Value == nil {
		return false, nil, fmt.Errorf("value : seuil numérique requis")
	}
	window := c.Window
	if window == "" {
		window = "5m"
	}
	dur, err := time.ParseDuration(window)
	if err != nil || dur <= 0 {
		return false, nil, fmt.Errorf("window invalide: %s", window)
	}
	agg := c.Aggregation
	if agg == "" {
		agg = "avg"
	}
	minSamples := 3
	if c.MinSamples != nil {
		minSamples = *c.MinSamples
	}
	if e.deps.QueryMetric == nil {
		return false, nil, nil
	}
	best, ok := metricwindow.Pick(e.deps.QueryMetric(c.Metric, c.Entity, dur, agg), c.Operator, *c.Value, minSamples)
	if !ok {
		return false, nil, nil
	}
	detail := map[string]any{"metric": c.Metric, "entity": best.Entity, "value": best.Value, "threshold": *c.Value,
		"window": window, "aggregation": agg}
	switch scope {
	case "host":
		// DisableProxy accepte le domaine à défaut d'identifiant, comme pour proxy_error_rate.
		detail["host"], detail["proxy_id"], detail["proxy_name"] = best.Entity, best.Entity, best.Entity
	case "edge":
		detail["node_name"] = best.Entity
	case "domain":
		detail["domain"] = best.Entity
	}
	return true, detail, nil
}
