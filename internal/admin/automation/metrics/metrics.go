// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package metrics garde une heure d'historique des métriques que l'Admin connaît (trafic des proxies et des
// passerelles, TLS, moteurs de sécurité…) pour la condition metric_threshold des flux. Les sources sont des
// fonctions fournies au branchement : le paquet ne dépend d'aucune d'elles.
package metrics

import (
	"time"

	"github.com/vincamok/goproxify/internal/admin/automation"
	"github.com/vincamok/goproxify/internal/metricwindow"
)

const (
	// Every est la période d'échantillonnage ; Keep la durée conservée.
	Every = 10 * time.Second
	Keep  = time.Hour
)

// Sample est une valeur relevée pour une série (métrique + entité).
type Sample = metricwindow.Sample

// Provider relève les valeurs courantes d'une source.
type Provider func() []Sample

// Store conserve les séries relevées.
type Store struct {
	defs      []automation.MetricDef
	providers []Provider
	win       *metricwindow.Window
}

// New crée un Store pour les métriques defs, alimenté par providers.
func New(defs []automation.MetricDef, providers ...Provider) *Store {
	return &Store{defs: defs, providers: providers, win: metricwindow.New(Keep)}
}

// Run relève les sources toutes les Every jusqu'à la fermeture de stop.
func (s *Store) Run(stop <-chan struct{}) {
	t := time.NewTicker(Every)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			s.Collect(now)
		case <-stop:
			return
		}
	}
}

// Collect relève les sources une fois à l'instant now.
func (s *Store) Collect(now time.Time) {
	known := map[string]bool{}
	for _, d := range s.defs {
		known[d.Key] = true
	}
	var samples []Sample
	for _, p := range s.providers {
		for _, sm := range p() {
			if known[sm.Key] {
				samples = append(samples, sm)
			}
		}
	}
	s.win.Add(now, samples)
}

// Catalog liste les métriques proposées.
func (s *Store) Catalog() []automation.MetricDef { return s.defs }

// Entities liste les entités qui ont des points pour key.
func (s *Store) Entities(key string) []string { return s.win.Entities(key) }

// Query agrège chaque série de key (ou la seule entité demandée) sur la fenêtre.
func (s *Store) Query(key, entity string, window time.Duration, agg string) []automation.MetricValue {
	var out []automation.MetricValue
	for _, v := range s.win.Query(key, entity, window, agg) {
		out = append(out, automation.MetricValue(v))
	}
	return out
}
