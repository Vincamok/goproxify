// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package metrics garde une heure d'historique des métriques que l'Admin connaît (trafic des proxies et des
// passerelles, TLS, moteurs de sécurité…) pour la condition metric_threshold des flux. Les sources sont des
// fonctions fournies au branchement : le paquet ne dépend d'aucune d'elles.
package metrics

import (
	"math"
	"sort"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/automation"
)

const (
	// Every est la période d'échantillonnage ; Keep la durée conservée.
	Every = 10 * time.Second
	Keep  = time.Hour
)

// Sample est une valeur relevée pour une série (métrique + entité).
type Sample struct {
	Key    string
	Entity string // "" pour une métrique globale
	Value  float64
}

// Provider relève les valeurs courantes d'une source.
type Provider func() []Sample

type point struct {
	t time.Time
	v float64
}

// Store conserve les séries relevées.
type Store struct {
	defs      []automation.MetricDef
	providers []Provider

	mu     sync.RWMutex
	series map[string]map[string][]point // métrique → entité → points (ordre chronologique)
}

// New crée un Store pour les métriques defs, alimenté par providers.
func New(defs []automation.MetricDef, providers ...Provider) *Store {
	return &Store{defs: defs, providers: providers, series: map[string]map[string][]point{}}
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
		samples = append(samples, p()...)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	for _, sm := range samples {
		if !known[sm.Key] || math.IsNaN(sm.Value) || math.IsInf(sm.Value, 0) {
			continue
		}
		byEntity := s.series[sm.Key]
		if byEntity == nil {
			byEntity = map[string][]point{}
			s.series[sm.Key] = byEntity
		}
		byEntity[sm.Entity] = append(byEntity[sm.Entity], point{t: now, v: sm.Value})
	}
	cutoff := now.Add(-Keep)
	for key, byEntity := range s.series {
		for entity, pts := range byEntity {
			i := sort.Search(len(pts), func(i int) bool { return pts[i].t.After(cutoff) })
			if i == len(pts) {
				delete(byEntity, entity) // entité muette depuis une heure
				continue
			}
			byEntity[entity] = append(pts[:0:0], pts[i:]...)
		}
		if len(byEntity) == 0 {
			delete(s.series, key)
		}
	}
}

// Catalog liste les métriques proposées.
func (s *Store) Catalog() []automation.MetricDef { return s.defs }

// Entities liste les entités qui ont des points pour key.
func (s *Store) Entities(key string) []string {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []string
	for e := range s.series[key] {
		if e != "" {
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// Query agrège chaque série de key (ou la seule entité demandée) sur la fenêtre.
func (s *Store) Query(key, entity string, window time.Duration, agg string) []automation.MetricValue {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var out []automation.MetricValue
	for e, pts := range s.series[key] {
		if entity != "" && e != entity {
			continue
		}
		if len(pts) == 0 {
			continue
		}
		from := pts[len(pts)-1].t.Add(-window)
		i := sort.Search(len(pts), func(i int) bool { return !pts[i].t.Before(from) })
		win := pts[i:]
		if len(win) == 0 {
			continue
		}
		out = append(out, automation.MetricValue{Entity: e, Value: aggregate(win, agg), Samples: len(win)})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Entity < out[j].Entity })
	return out
}

func aggregate(pts []point, agg string) float64 {
	switch agg {
	case "last":
		return pts[len(pts)-1].v
	case "min", "max":
		v := pts[0].v
		for _, p := range pts[1:] {
			if (agg == "min" && p.v < v) || (agg == "max" && p.v > v) {
				v = p.v
			}
		}
		return v
	case "increase", "rate":
		// Un compteur qui redescend a été remis à zéro (redémarrage) : la nouvelle valeur est l'augmentation.
		inc := 0.0
		for i := 1; i < len(pts); i++ {
			if d := pts[i].v - pts[i-1].v; d >= 0 {
				inc += d
			} else {
				inc += pts[i].v
			}
		}
		if agg == "increase" {
			return inc
		}
		span := pts[len(pts)-1].t.Sub(pts[0].t).Seconds()
		if span <= 0 {
			return 0
		}
		return inc / span
	}
	sum := 0.0
	for _, p := range pts {
		sum += p.v
	}
	return sum / float64(len(pts))
}
