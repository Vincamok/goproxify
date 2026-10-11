// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package metrics

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/automation"
)

func TestStoreAggregatesAndForgets(t *testing.T) {
	values := []float64{10, 20, 30, 5, 15} // compteur remis à zéro entre 30 et 5
	i := 0
	s := New([]automation.MetricDef{{Key: "c", Kind: "counter", Scope: "host"}, {Key: "g", Kind: "gauge", Scope: "global"}},
		func() []Sample {
			v := values[i]
			i++
			return []Sample{{Key: "c", Entity: "a.example", Value: v}, {Key: "g", Value: v}, {Key: "inconnue", Value: 1}}
		})
	t0 := time.Date(2026, 1, 1, 12, 0, 0, 0, time.UTC)
	for n := range values {
		s.Collect(t0.Add(time.Duration(n) * 10 * time.Second))
	}
	q := func(key, agg string, window time.Duration) automation.MetricValue {
		t.Helper()
		got := s.Query(key, "", window, agg)
		if len(got) != 1 {
			t.Fatalf("%s/%s : %d séries", key, agg, len(got))
		}
		return got[0]
	}
	for agg, want := range map[string]float64{"avg": 16, "min": 5, "max": 30, "last": 15} {
		if v := q("g", agg, time.Hour); v.Value != want || v.Samples != 5 {
			t.Errorf("%s : %v (%d points), attendu %v", agg, v.Value, v.Samples, want)
		}
	}
	// 10→20→30 (+20), remise à zéro (+5), 5→15 (+10)
	if v := q("c", "increase", time.Hour); v.Value != 35 {
		t.Errorf("increase : %v, attendu 35", v.Value)
	}
	if v := q("c", "rate", time.Hour); v.Value != 35.0/40 {
		t.Errorf("rate : %v", v.Value)
	}
	if v := q("g", "avg", 15*time.Second); v.Samples != 2 || v.Value != 10 {
		t.Errorf("fenêtre courte : %+v", v)
	}
	if e := s.Entities("c"); len(e) != 1 || e[0] != "a.example" {
		t.Errorf("entités : %v", e)
	}
	if got := s.Query("inconnue", "", time.Hour, "avg"); len(got) != 0 {
		t.Errorf("métrique hors catalogue conservée : %v", got)
	}

	values = append(values, 1)
	s.providers = []Provider{func() []Sample { return nil }}
	s.Collect(t0.Add(2 * time.Hour))
	if got := s.Query("g", "", time.Hour, "avg"); len(got) != 0 {
		t.Errorf("série muette depuis une heure conservée : %v", got)
	}
}
