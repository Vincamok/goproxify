// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package metricwindow garde une courte histoire de séries (métrique + entité) et les agrège sur une
// fenêtre, pour la condition « Seuil sur une métrique » des flux. L'Admin l'alimente avec la vue du
// cluster, chaque passerelle avec son propre trafic : la même condition s'évalue des deux côtés.
package metricwindow

import (
	"math"
	"sort"
	"sync"
	"time"
)

// Sample est une valeur relevée pour une série.
type Sample struct {
	Key    string
	Entity string // "" pour une métrique globale
	Value  float64
}

// Value est l'agrégat d'une série sur la fenêtre.
type Value struct {
	Entity  string
	Value   float64
	Samples int
}

type point struct {
	t time.Time
	v float64
}

// Window conserve les points des Keep dernières secondes de chaque série.
type Window struct {
	Keep time.Duration

	mu     sync.RWMutex
	series map[string]map[string][]point // métrique → entité → points (ordre chronologique)
}

// New crée une Window qui conserve keep d'historique.
func New(keep time.Duration) *Window {
	return &Window{Keep: keep, series: map[string]map[string][]point{}}
}

// Add enregistre les valeurs relevées à l'instant now et oublie ce qui sort de la fenêtre conservée.
func (w *Window) Add(now time.Time, samples []Sample) {
	w.mu.Lock()
	defer w.mu.Unlock()
	for _, sm := range samples {
		if math.IsNaN(sm.Value) || math.IsInf(sm.Value, 0) {
			continue
		}
		byEntity := w.series[sm.Key]
		if byEntity == nil {
			byEntity = map[string][]point{}
			w.series[sm.Key] = byEntity
		}
		byEntity[sm.Entity] = append(byEntity[sm.Entity], point{t: now, v: sm.Value})
	}
	cutoff := now.Add(-w.Keep)
	for key, byEntity := range w.series {
		for entity, pts := range byEntity {
			i := sort.Search(len(pts), func(i int) bool { return pts[i].t.After(cutoff) })
			if i == len(pts) {
				delete(byEntity, entity) // entité muette depuis toute la fenêtre conservée
				continue
			}
			byEntity[entity] = append(pts[:0:0], pts[i:]...)
		}
		if len(byEntity) == 0 {
			delete(w.series, key)
		}
	}
}

// Entities liste les entités qui ont des points pour key.
func (w *Window) Entities(key string) []string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []string
	for e := range w.series[key] {
		if e != "" {
			out = append(out, e)
		}
	}
	sort.Strings(out)
	return out
}

// Query agrège chaque série de key (ou la seule entité demandée) sur la fenêtre.
func (w *Window) Query(key, entity string, window time.Duration, agg string) []Value {
	w.mu.RLock()
	defer w.mu.RUnlock()
	var out []Value
	for e, pts := range w.series[key] {
		if (entity != "" && e != entity) || len(pts) == 0 {
			continue
		}
		from := pts[len(pts)-1].t.Add(-window)
		i := sort.Search(len(pts), func(i int) bool { return !pts[i].t.Before(from) })
		win := pts[i:]
		if len(win) == 0 {
			continue
		}
		out = append(out, Value{Entity: e, Value: aggregate(win, agg), Samples: len(win)})
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

// Compare applique l'opérateur d'une condition de seuil (">" par défaut).
func Compare(op string, v, threshold float64) bool {
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

// Pick retient, parmi les séries qui franchissent le seuil avec assez de points, la plus éloignée du
// seuil (la pire, la plus parlante dans une notification). ok est faux si aucune ne le franchit.
func Pick(values []Value, op string, threshold float64, minSamples int) (best Value, ok bool) {
	for _, v := range values {
		if v.Samples < minSamples || math.IsNaN(v.Value) || !Compare(op, v.Value, threshold) {
			continue
		}
		if !ok || math.Abs(v.Value-threshold) > math.Abs(best.Value-threshold) {
			best, ok = v, true
		}
	}
	return best, ok
}
