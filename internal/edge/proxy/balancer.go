// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net"
	"net/http"
	"net/url"
	"sync"
	"sync/atomic"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Balancer choisit un backend pour chaque requête.
type Balancer interface {
	Next(r *http.Request) *router.Backend
}

// ---- Round Robin --------------------------------------------------------

type roundRobin struct {
	backends []router.Backend
	idx      atomic.Uint64
}

func newRoundRobin(bs []router.Backend) *roundRobin {
	return &roundRobin{backends: bs}
}

func (rr *roundRobin) Next(_ *http.Request) *router.Backend {
	if len(rr.backends) == 0 {
		return nil
	}
	i := rr.idx.Add(1) - 1
	b := &rr.backends[i%uint64(len(rr.backends))]
	return b
}

// ---- Weighted -----------------------------------------------------------

type weighted struct {
	backends []router.Backend
	weights  []int
	total    int
	idx      atomic.Uint64
}

func newWeighted(bs []router.Backend) *weighted {
	total := 0
	weights := make([]int, len(bs))
	for i, b := range bs {
		w := b.Weight
		if w <= 0 {
			w = 1
		}
		weights[i] = w
		total += w
	}
	return &weighted{backends: bs, weights: weights, total: total}
}

func (w *weighted) Next(_ *http.Request) *router.Backend {
	if len(w.backends) == 0 {
		return nil
	}
	n := int(w.idx.Add(1)-1) % w.total
	acc := 0
	for i, wt := range w.weights {
		acc += wt
		if n < acc {
			return &w.backends[i]
		}
	}
	return &w.backends[0]
}

// ---- Sticky session (cookie) -------------------------------------------

type sticky struct {
	inner      Balancer
	backends   []router.Backend
	cookieName string
}

func newSticky(inner Balancer, bs []router.Backend, cookieName string) *sticky {
	return &sticky{inner: inner, backends: bs, cookieName: cookieName}
}

func (s *sticky) Next(r *http.Request) *router.Backend {
	if c, err := r.Cookie(s.cookieName); err == nil {
		for i := range s.backends {
			if s.backends[i].URL == c.Value {
				return &s.backends[i]
			}
		}
	}
	return s.inner.Next(r)
}

// ---- Circuit Breaker ----------------------------------------------------

type cbState int

const (
	cbClosed   cbState = iota
	cbOpen     cbState = iota
	cbHalfOpen cbState = iota
)

type cbBackend struct {
	failures   int
	state      cbState
	openUntil  time.Time
	probeUntil time.Time // half-open : sonde en vol jusqu'à cette date
}

// circuitBreaker tient un état par backend. Il n'est pas dans la chaîne Balancer :
// le handler filtre ses candidats avec Allow, ce qui court-circuite réellement les tentatives.
type circuitBreaker struct {
	mu       sync.Mutex
	cfg      *router.CBConfig
	backends map[string]*cbBackend
}

func newCB(cfg *router.CBConfig) *circuitBreaker {
	return &circuitBreaker{cfg: cfg, backends: map[string]*cbBackend{}}
}

func (cb *circuitBreaker) get(url string) *cbBackend {
	s := cb.backends[url]
	if s == nil {
		s = &cbBackend{}
		cb.backends[url] = s
	}
	return s
}

// Allow indique si le backend peut être tenté. Ouvert : non, jusqu'à l'échéance.
// Ensuite half-open : une seule sonde à la fois (expire après Timeout si perdue).
func (cb *circuitBreaker) Allow(url string) bool {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	s := cb.get(url)
	now := time.Now()
	switch s.state {
	case cbOpen:
		if now.Before(s.openUntil) {
			return false
		}
		s.state = cbHalfOpen
	case cbHalfOpen:
		if now.Before(s.probeUntil) {
			return false
		}
	default:
		return true
	}
	s.probeUntil = now.Add(cb.cfg.Timeout)
	return true
}

// RetryAfter donne le délai minimal avant qu'un des backends redevienne tentable.
func (cb *circuitBreaker) RetryAfter(urls []string) time.Duration {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	now := time.Now()
	var best time.Duration
	for _, u := range urls {
		s := cb.get(u)
		until := s.openUntil
		if s.state == cbHalfOpen {
			until = s.probeUntil
		}
		if d := until.Sub(now); d > 0 && (best == 0 || d < best) {
			best = d
		}
	}
	return best
}

func (cb *circuitBreaker) RecordSuccess(url string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	s := cb.get(url)
	s.failures = 0
	s.state = cbClosed
}

func (cb *circuitBreaker) RecordFailure(url string) {
	cb.mu.Lock()
	defer cb.mu.Unlock()
	s := cb.get(url)
	s.failures++
	if s.state == cbHalfOpen || s.failures >= cb.cfg.Threshold {
		s.state = cbOpen
		s.openUntil = time.Now().Add(cb.cfg.Timeout)
	}
}

// ---- Adaptive (least-load) ----------------------------------------------

// metricsScorer est une interface minimale pour injecter AgentMetricsStore sans import circulaire.
type metricsScorer interface {
	Score(hostIP string) float64
}

type adaptive struct {
	backends []router.Backend
	metrics  metricsScorer
	fallback Balancer
}

func newAdaptive(bs []router.Backend, m metricsScorer) *adaptive {
	return &adaptive{backends: bs, metrics: m, fallback: newRoundRobin(bs)}
}

func (a *adaptive) Next(_ *http.Request) *router.Backend {
	if len(a.backends) == 0 {
		return nil
	}
	bestIdx := -1
	bestScore := float64(1 << 62)
	scored := 0
	for i := range a.backends {
		ip := backendIP(a.backends[i].URL)
		score := float64(-1)
		if a.metrics != nil {
			score = a.metrics.Score(ip)
		}
		if score < 0 {
			continue
		}
		scored++
		if score < bestScore {
			bestScore = score
			bestIdx = i
		}
	}
	// Aucune métrique → round-robin ; sinon choisir parmi les backends scorés.
	if scored == 0 || bestIdx < 0 {
		return a.fallback.Next(nil)
	}
	return &a.backends[bestIdx]
}

// backendIP extrait l'IP hôte d'une URL de backend.
func backendIP(rawURL string) string {
	u, err := url.Parse(rawURL)
	if err != nil {
		return rawURL
	}
	host := u.Hostname()
	if ip := net.ParseIP(host); ip != nil {
		return ip.String()
	}
	// hostname DNS : retourne tel quel, ne sera probablement pas dans les métriques
	return host
}

// NewBalancer construit la chaîne balancer pour une route.
// Retourne également le *circuitBreaker s'il est configuré (nil sinon),
// pour permettre au handler d'enregistrer les succès/échecs.
func NewBalancer(route *router.Route, metrics metricsScorer) (Balancer, *circuitBreaker) {
	bs := route.Backends
	var b Balancer
	switch route.LB {
	case router.LBWeighted:
		b = newWeighted(bs)
	case router.LBAdaptive:
		if metrics != nil {
			b = newAdaptive(bs, metrics)
		} else {
			b = newRoundRobin(bs)
		}
	default:
		b = newRoundRobin(bs)
	}
	if route.StickyCookie != "" {
		b = newSticky(b, bs, route.StickyCookie)
	}
	var cb *circuitBreaker
	if route.CircuitBreaker != nil {
		cb = newCB(route.CircuitBreaker)
	}
	return b, cb
}
