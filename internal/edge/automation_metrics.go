// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	dto "github.com/prometheus/client_model/go"

	"github.com/vincamok/goproxify/internal/metricwindow"
)

const (
	localMetricsEvery = 10 * time.Second
	localMetricsKeep  = time.Hour
)

// localMetrics garde une heure des métriques de cette passerelle (edgere.MetricScopes) pour les flux à
// condition « Seuil sur une métrique » qu'elle exécute. Elles sont calculées comme le fait l'Admin, mais
// sur le seul trafic de la passerelle, à partir de ses compteurs : rien ne dépend de l'Admin. L'historique
// vit en mémoire ; après un redémarrage, le nombre de points minimum de la condition évite de conclure
// sur trop peu de données.
type localMetrics struct {
	node   string
	win    *metricwindow.Window
	prev   map[string]hostCum
	prevAt time.Time
}

// hostCum : compteurs cumulés d'un domaine, tels que lus dans Prometheus.
type hostCum struct {
	req, errs, sum, count float64
	buckets               map[float64]float64
}

func newLocalMetrics(node string) *localMetrics {
	return &localMetrics{node: node, win: metricwindow.New(localMetricsKeep)}
}

func (m *localMetrics) run(ctx context.Context) {
	t := time.NewTicker(localMetricsEvery)
	defer t.Stop()
	for {
		select {
		case now := <-t.C:
			if mfs, err := prometheus.DefaultGatherer.Gather(); err == nil {
				m.collect(now, mfs)
			}
		case <-ctx.Done():
			return
		}
	}
}

func (m *localMetrics) query(key, entity string, window time.Duration, agg string) []metricwindow.Value {
	return m.win.Query(key, entity, window, agg)
}

// collect relève un instantané des compteurs. Débit, erreurs et P95 portent sur l'intervalle écoulé depuis
// le relevé précédent ; un compteur qui redescend (remise à zéro) compte en entier.
func (m *localMetrics) collect(now time.Time, mfs []*dto.MetricFamily) {
	idx := make(map[string]*dto.MetricFamily, len(mfs))
	for _, mf := range mfs {
		idx[mf.GetName()] = mf
	}
	cur := map[string]hostCum{}
	host := func(h string) hostCum {
		c, ok := cur[h]
		if !ok {
			c.buckets = map[float64]float64{}
		}
		return c
	}
	for _, x := range familyMetrics(idx, "gpx_edge_requests_total") {
		h := labelVal(x.GetLabel(), "host")
		if h == "" {
			continue
		}
		c := host(h)
		c.req += x.GetCounter().GetValue()
		if st := labelVal(x.GetLabel(), "status"); st != "" && st[0] == '5' {
			c.errs += x.GetCounter().GetValue()
		}
		cur[h] = c
	}
	for _, x := range familyMetrics(idx, "gpx_edge_request_duration_seconds") {
		h := labelVal(x.GetLabel(), "host")
		if h == "" {
			continue
		}
		c := host(h)
		hist := x.GetHistogram()
		c.sum += hist.GetSampleSum()
		c.count += float64(hist.GetSampleCount())
		for _, b := range hist.GetBucket() {
			c.buckets[b.GetUpperBound()] += float64(b.GetCumulativeCount())
		}
		cur[h] = c
	}

	var samples []metricwindow.Sample
	add := func(key, entity string, v float64) {
		samples = append(samples, metricwindow.Sample{Key: key, Entity: entity, Value: v})
	}
	dt := now.Sub(m.prevAt).Seconds()
	if m.prev != nil && dt > 0 {
		total := hostCum{buckets: map[float64]float64{}}
		for h, c := range cur {
			p, known := m.prev[h]
			if !known || c.req < p.req || c.errs < p.errs || c.count < p.count {
				p = hostCum{}
			}
			d := hostCum{req: c.req - p.req, errs: c.errs - p.errs, sum: c.sum - p.sum, count: c.count - p.count,
				buckets: map[float64]float64{}}
			for le, n := range c.buckets {
				d.buckets[le] = n - p.buckets[le]
				total.buckets[le] += d.buckets[le]
			}
			total.req += d.req
			total.errs += d.errs
			total.sum += d.sum
			total.count += d.count
			add("proxy.error_rate_pct", h, errPct(d))
			add("proxy.p95_ms", h, bucketQuantile(d.buckets, d.count, d.sum, 0.95)*1000)
		}
		if m.node != "" {
			add("edge.rps", m.node, total.req/dt)
			add("edge.error_rate_pct", m.node, errPct(total))
			add("edge.p95_ms", m.node, bucketQuantile(total.buckets, total.count, total.sum, 0.95)*1000)
		}
	}
	m.prev, m.prevAt = cur, now

	certDays := map[string]float64{}
	for _, x := range familyMetrics(idx, "gpx_tls_cert_expiry_seconds") {
		d := labelVal(x.GetLabel(), "domain")
		v := x.GetGauge().GetValue() / 86400
		if old, ok := certDays[d]; d != "" && (!ok || v < old) {
			certDays[d] = v
		}
	}
	for d, v := range certDays {
		add("tls.cert_expires_days", d, v)
	}
	for _, x := range familyMetrics(idx, "gpx_tls_handshake_seconds") {
		h, hist := labelVal(x.GetLabel(), "host"), x.GetHistogram()
		if h == "" || hist.GetSampleCount() == 0 {
			continue
		}
		b := map[float64]float64{}
		for _, bk := range hist.GetBucket() {
			b[bk.GetUpperBound()] += float64(bk.GetCumulativeCount())
		}
		add("tls.handshake_p95_ms", h, bucketQuantile(b, float64(hist.GetSampleCount()), hist.GetSampleSum(), 0.95)*1000)
	}
	for _, x := range familyMetrics(idx, "gpx_tls_active_connections") {
		if h := labelVal(x.GetLabel(), "host"); h != "" {
			add("tls.active_connections", h, x.GetGauge().GetValue())
		}
	}
	m.win.Add(now, samples)
}

func familyMetrics(idx map[string]*dto.MetricFamily, name string) []*dto.Metric {
	if mf, ok := idx[name]; ok {
		return mf.GetMetric()
	}
	return nil
}

func errPct(c hostCum) float64 {
	if c.req <= 0 {
		return 0
	}
	return c.errs / c.req * 100
}
