// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"sort"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/modules"
)

// EventDef décrit un événement proposé au déclencheur « événement ».
type EventDef struct {
	Type    string   `json:"type"`
	Label   string   `json:"label"`
	Outputs []string `json:"outputs"`
}

// Catalog liste tout ce qu'un flux peut contenir : l'éditeur se construit à partir de lui.
type Catalog struct {
	Triggers   []modules.Manifest `json:"triggers"`
	Events     []EventDef         `json:"events"`
	Conditions []modules.Manifest `json:"conditions"`
	Actions    []modules.Manifest `json:"actions"`
	Steps      []modules.Manifest `json:"steps"`
	Metrics    []MetricDef        `json:"metrics"`
	// Variables toujours disponibles, en plus des sorties du déclencheur et des étapes précédentes.
	Variables []string `json:"variables"`
}

// Catalog retourne le catalogue.
func (s *Service) Catalog() Catalog {
	c := Catalog{
		Triggers:   triggerManifests,
		Conditions: ConditionManifests(),
		Actions:    ActionManifests(),
		Steps:      stepManifests,
		Metrics:    []MetricDef{},
		Variables:  []string{"flow.id", "flow.name", "run.id"},
	}
	for _, tr := range alerting.AllTriggers {
		outputs := append([]string{"event", "severity", "node_name", "domain", "component"}, alerting.TriggerOutputs[tr]...)
		c.Events = append(c.Events, EventDef{Type: string(tr), Label: alerting.TriggerLabels[tr], Outputs: outputs})
	}
	if s.deps.Metrics != nil {
		c.Metrics = s.deps.Metrics.Catalog()
	}
	return c
}

// Options retourne les valeurs proposées par un champ select à source dynamique (modules.Field.Source).
func (s *Service) Options(ctx context.Context, source string) ([]modules.Option, error) {
	out := []modules.Option{}
	query := func(q string, args ...any) error {
		rows, err := s.db.QueryContext(ctx, q, args...)
		if err != nil {
			return err
		}
		defer rows.Close()
		for rows.Next() {
			var o modules.Option
			if rows.Scan(&o.Value, &o.Label) == nil {
				out = append(out, o)
			}
		}
		return rows.Err()
	}
	switch source {
	case "proxies":
		return out, query(`SELECT id, name || ' (' || COALESCE(json_extract(config,'$.domain'),'') || ')' FROM proxies ORDER BY name COLLATE NOCASE`)
	case "nodes":
		return out, query(`SELECT node_name, node_name || ' (' || role || ')' FROM nodes ORDER BY node_name`)
	case "domains":
		return out, query(`SELECT d, d FROM (SELECT domain AS d FROM certs UNION SELECT json_extract(config,'$.domain') FROM proxies)
			WHERE d IS NOT NULL AND d != '' ORDER BY d`)
	case "alert_channels":
		return out, query(`SELECT id, name || ' (' || type || ')' FROM alert_channels ORDER BY name COLLATE NOCASE`)
	case "flows:manual":
		return out, query(`SELECT id, name FROM flows WHERE trigger_kind=? ORDER BY name COLLATE NOCASE`, string(TriggerManual))
	case "events":
		for _, tr := range alerting.AllTriggers {
			out = append(out, modules.Option{Value: string(tr), Label: alerting.TriggerLabels[tr]})
		}
	case "metrics":
		if s.deps.Metrics != nil {
			for _, m := range s.deps.Metrics.Catalog() {
				label := m.Label
				if m.Unit != "" {
					label += " (" + m.Unit + ")"
				}
				out = append(out, modules.Option{Value: m.Key, Label: label})
			}
		}
	case "metric_entities":
		if s.deps.Metrics != nil {
			seen := map[string]bool{}
			for _, m := range s.deps.Metrics.Catalog() {
				for _, e := range s.deps.Metrics.Entities(m.Key) {
					if !seen[e] {
						seen[e] = true
						out = append(out, modules.Option{Value: e, Label: e})
					}
				}
			}
			sort.Slice(out, func(i, j int) bool { return out[i].Value < out[j].Value })
		}
	default:
		return nil, invalid("source de valeurs %q inconnue", source)
	}
	return out, nil
}
