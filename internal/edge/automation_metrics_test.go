// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"testing"
	"time"

	dto "github.com/prometheus/client_model/go"
	"google.golang.org/protobuf/proto"
)

func counterFamily(name string, series map[[2]string]float64) *dto.MetricFamily {
	mf := &dto.MetricFamily{Name: proto.String(name)}
	for k, v := range series {
		mf.Metric = append(mf.Metric, &dto.Metric{
			Label:   []*dto.LabelPair{{Name: proto.String("host"), Value: proto.String(k[0])}, {Name: proto.String("status"), Value: proto.String(k[1])}},
			Counter: &dto.Counter{Value: proto.Float64(v)},
		})
	}
	return mf
}

func durationFamily(host string, count uint64, sum float64, buckets map[float64]uint64) *dto.MetricFamily {
	h := &dto.Histogram{SampleCount: proto.Uint64(count), SampleSum: proto.Float64(sum)}
	for le, n := range buckets {
		h.Bucket = append(h.Bucket, &dto.Bucket{UpperBound: proto.Float64(le), CumulativeCount: proto.Uint64(n)})
	}
	return &dto.MetricFamily{Name: proto.String("gpx_edge_request_duration_seconds"), Metric: []*dto.Metric{{
		Label: []*dto.LabelPair{{Name: proto.String("host"), Value: proto.String(host)}}, Histogram: h}}}
}

func TestLocalMetricsWindowedFromCounters(t *testing.T) {
	m := newLocalMetrics("paris-01")
	t0 := time.Date(2026, 10, 12, 9, 0, 0, 0, time.UTC)
	snap := func(at time.Time, ok, ko float64, count uint64, fast, slow uint64) {
		m.collect(at, []*dto.MetricFamily{
			counterFamily("gpx_edge_requests_total", map[[2]string]float64{{"a.example", "2xx"}: ok, {"a.example", "5xx"}: ko}),
			durationFamily("a.example", count, float64(count)*0.1, map[float64]uint64{0.1: fast, 1: slow}),
		})
	}
	snap(t0, 100, 0, 100, 100, 100)
	if got := m.query("edge.rps", "", time.Hour, "last"); len(got) != 0 {
		t.Fatalf("premier relevé : pas de différence possible, %v", got)
	}
	// 10 s plus tard : 90 réussites et 10 erreurs, dont 50 au-delà de 100 ms.
	snap(t0.Add(10*time.Second), 190, 10, 200, 150, 200)
	last := func(key, entity string) float64 {
		t.Helper()
		got := m.query(key, entity, time.Hour, "last")
		if len(got) != 1 {
			t.Fatalf("%s/%s : %v", key, entity, got)
		}
		return got[0].Value
	}
	if v := last("edge.rps", "paris-01"); v != 10 {
		t.Errorf("edge.rps : %v", v)
	}
	if v := last("proxy.error_rate_pct", "a.example"); v != 10 {
		t.Errorf("taux d'erreurs : %v", v)
	}
	if v := last("proxy.p95_ms", "a.example"); v <= 100 || v > 1000 {
		t.Errorf("p95 de l'intervalle : %v", v)
	}
	// Redémarrage : les compteurs repartent de zéro, le nouveau cumul compte en entier.
	snap(t0.Add(20*time.Second), 20, 0, 20, 20, 20)
	if v := last("edge.rps", "paris-01"); v != 2 {
		t.Errorf("après remise à zéro : %v", v)
	}
	if v := last("proxy.error_rate_pct", "a.example"); v != 0 {
		t.Errorf("taux d'erreurs après remise à zéro : %v", v)
	}
}
