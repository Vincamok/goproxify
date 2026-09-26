// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"sort"
	"strconv"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
)

const (
	proxyMetricsInterval = 10 * time.Second
	proxyMetricsCapacity = 360 // 1 h à 10 s
	proxyMetricsIdleTTL  = time.Hour
)

var proxyMetricsClient = &http.Client{Timeout: 5 * time.Second}

type latBucket struct {
	Le    float64 `json:"le"`
	Count float64 `json:"count"`
}

// hostCounters : compteurs cumulatifs d'un host, tels que publiés par une passerelle.
type hostCounters struct {
	Host           string      `json:"host"`
	Requests       float64     `json:"requests"`
	Errors         float64     `json:"errors"`
	DurationSumS   float64     `json:"duration_sum_s"`
	DurationCount  float64     `json:"duration_count"`
	LatencyBuckets []latBucket `json:"latency_buckets"`
}

// ProxyMetricSample : un point de la série d'un host (fenêtre = un intervalle de relevé).
type ProxyMetricSample struct {
	T       time.Time
	RPS     float64
	ErrRate float64 // fraction 0..1 de réponses 5xx
	P95ms   float64
}

type hostWindow struct {
	requests, errors, sumS, count float64
	rps                           float64
	buckets                       map[float64]float64
}

// ProxyMetricsSampler interroge périodiquement les passerelles et conserve, par host, une série
// de débit / erreurs / p95 en mémoire. Les compteurs Prometheus sont cumulatifs : chaque point est
// la différence entre deux relevés successifs d'une même passerelle (une remise à zéro après
// redémarrage est détectée), puis les passerelles sont additionnées.
type ProxyMetricsSampler struct {
	DB  *sql.DB
	Log *slog.Logger

	mu        sync.RWMutex
	prev      map[string]map[string]hostCounters // passerelle → host → compteurs
	prevAt    map[string]time.Time
	series    map[string][]ProxyMetricSample
	lastSeen  map[string]time.Time
	sampledAt time.Time
}

func NewProxyMetricsSampler(db *sql.DB, log *slog.Logger) *ProxyMetricsSampler {
	return &ProxyMetricsSampler{
		DB: db, Log: log,
		prev:     map[string]map[string]hostCounters{},
		prevAt:   map[string]time.Time{},
		series:   map[string][]ProxyMetricSample{},
		lastSeen: map[string]time.Time{},
	}
}

// Run relève les passerelles jusqu'à l'annulation du contexte.
func (s *ProxyMetricsSampler) Run(ctx context.Context) {
	t := time.NewTicker(proxyMetricsInterval)
	defer t.Stop()
	for {
		s.Sample(ctx)
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

type edgeCred struct{ name, endpoint, token string }

func (s *ProxyMetricsSampler) edges(ctx context.Context) []edgeCred {
	rows, err := s.DB.QueryContext(ctx,
		`SELECT node_name, node_endpoint, token FROM tokens
		 WHERE role='edge' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)
		 ORDER BY created_at DESC`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []edgeCred
	for rows.Next() {
		var c edgeCred
		if rows.Scan(&c.name, &c.endpoint, &c.token) != nil || seen[c.name] {
			continue
		}
		seen[c.name] = true
		out = append(out, c)
	}
	return out
}

func (s *ProxyMetricsSampler) fetch(ctx context.Context, c edgeCred) ([]hostCounters, bool) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.endpoint+"/internal/v1/metrics/summary", nil)
	if err != nil {
		return nil, false
	}
	req.Header.Set("Authorization", "Bearer "+auth.PlainNodeToken(c.token))
	resp, err := proxyMetricsClient.Do(req)
	if err != nil {
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, false
	}
	var payload struct {
		Proxies []hostCounters `json:"proxies"`
	}
	if json.NewDecoder(resp.Body).Decode(&payload) != nil {
		return nil, false
	}
	return payload.Proxies, true
}

// Sample effectue un relevé de toutes les passerelles.
func (s *ProxyMetricsSampler) Sample(ctx context.Context) {
	edges := s.edges(ctx)
	if len(edges) == 0 {
		return
	}
	type result struct {
		name  string
		stats []hostCounters
		ok    bool
	}
	res := make(chan result, len(edges))
	for _, c := range edges {
		go func(c edgeCred) {
			st, ok := s.fetch(ctx, c)
			res <- result{c.name, st, ok}
		}(c)
	}
	now := time.Now()
	acc := map[string]*hostWindow{}
	for range edges {
		r := <-res
		if r.ok {
			s.ingestEdge(acc, r.name, r.stats, now)
		}
	}
	s.commit(acc, now)
}

// ingestEdge compare un relevé au précédent de la même passerelle et cumule la fenêtre dans acc.
func (s *ProxyMetricsSampler) ingestEdge(acc map[string]*hostWindow, edge string, stats []hostCounters, now time.Time) {
	s.mu.Lock()
	prevStats := s.prev[edge]
	prevAt := s.prevAt[edge]
	cur := make(map[string]hostCounters, len(stats))
	for _, st := range stats {
		cur[st.Host] = st
	}
	s.prev[edge] = cur
	s.prevAt[edge] = now
	s.mu.Unlock()

	dt := now.Sub(prevAt).Seconds()
	if prevStats == nil || dt <= 0 {
		return // premier relevé de cette passerelle : pas de différence possible
	}
	for host, c := range cur {
		w := acc[host]
		if w == nil {
			w = &hostWindow{buckets: map[float64]float64{}}
			acc[host] = w
		}
		p, known := prevStats[host]
		reset := known && (c.Requests < p.Requests || c.Errors < p.Errors || c.DurationCount < p.DurationCount)
		if !known || reset {
			p = hostCounters{} // nouveau host ou compteurs remis à zéro : tout le cumul est neuf
		}
		dReq := c.Requests - p.Requests
		w.requests += dReq
		w.errors += c.Errors - p.Errors
		w.sumS += c.DurationSumS - p.DurationSumS
		w.count += c.DurationCount - p.DurationCount
		w.rps += dReq / dt
		pb := make(map[float64]float64, len(p.LatencyBuckets))
		for _, b := range p.LatencyBuckets {
			pb[b.Le] = b.Count
		}
		for _, b := range c.LatencyBuckets {
			w.buckets[b.Le] += b.Count - pb[b.Le]
		}
	}
}

func (s *ProxyMetricsSampler) commit(acc map[string]*hostWindow, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for host, w := range acc {
		sm := ProxyMetricSample{T: now, RPS: w.rps}
		if w.requests > 0 {
			sm.ErrRate = w.errors / w.requests
		}
		sm.P95ms = windowQuantile(w.buckets, w.count, w.sumS, 0.95) * 1000
		ser := append(s.series[host], sm)
		if len(ser) > proxyMetricsCapacity {
			ser = ser[len(ser)-proxyMetricsCapacity:]
		}
		s.series[host] = ser
		s.lastSeen[host] = now
	}
	for host, seen := range s.lastSeen {
		if now.Sub(seen) > proxyMetricsIdleTTL {
			delete(s.series, host)
			delete(s.lastSeen, host)
		}
	}
	if len(acc) > 0 {
		s.sampledAt = now
	}
}

// windowQuantile : quantile (secondes) d'un histogramme à buckets cumulatifs.
func windowQuantile(buckets map[float64]float64, count, sum, q float64) float64 {
	if count <= 0 {
		return 0
	}
	bounds := make([]float64, 0, len(buckets))
	for b := range buckets {
		bounds = append(bounds, b)
	}
	sort.Float64s(bounds)
	target := q * count
	var prevBound, prevCount float64
	for _, b := range bounds {
		c := buckets[b]
		if c >= target {
			if c == prevCount {
				return b
			}
			return prevBound + (b-prevBound)*(target-prevCount)/(c-prevCount)
		}
		prevBound, prevCount = b, c
	}
	return sum / count
}

type ProxyMetricsEntry struct {
	Host              string    `json:"host"`
	RequestsPerSecond float64   `json:"requests_per_second"`
	ErrorRate         float64   `json:"error_rate"`
	P95ms             float64   `json:"p95_ms"`
	Series            []float64 `json:"series"`
}

// Snapshot renvoie, par host, le dernier point (débit, erreurs, p95) et la série de débit des
// `points` derniers relevés (10 s d'écart), plus la date du dernier relevé (nil tant qu'aucun
// n'a abouti). Partagé par l'API HTTP et l'outil MCP get_proxy_metrics.
func (s *ProxyMetricsSampler) Snapshot(points int) ([]ProxyMetricsEntry, any) {
	if points <= 0 {
		points = 60
	}
	points = min(points, proxyMetricsCapacity)
	s.mu.RLock()
	out := make([]ProxyMetricsEntry, 0, len(s.series))
	for host, ser := range s.series {
		if len(ser) == 0 {
			continue
		}
		last := ser[len(ser)-1]
		tail := ser
		if len(tail) > points {
			tail = tail[len(tail)-points:]
		}
		rps := make([]float64, len(tail))
		for i, p := range tail {
			rps[i] = p.RPS
		}
		out = append(out, ProxyMetricsEntry{
			Host: host, RequestsPerSecond: last.RPS, ErrorRate: last.ErrRate, P95ms: last.P95ms, Series: rps,
		})
	}
	var sampledAt any
	if !s.sampledAt.IsZero() {
		sampledAt = s.sampledAt
	}
	s.mu.RUnlock()
	sort.Slice(out, func(i, j int) bool { return out[i].Host < out[j].Host })
	return out, sampledAt
}

// ServeHTTP : GET /api/v1/metrics/proxies?points=60 — voir Snapshot. Vide tant qu'aucune
// passerelle n'a été relevée deux fois.
func (s *ProxyMetricsSampler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	points, _ := strconv.Atoi(r.URL.Query().Get("points"))
	out, sampledAt := s.Snapshot(points)
	jsonOK(w, map[string]any{
		"interval_s": int(proxyMetricsInterval / time.Second),
		"sampled_at": sampledAt,
		"proxies":    out,
	})
}
