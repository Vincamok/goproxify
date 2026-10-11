// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"context"
	"net"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

const (
	// passiveDownTTL : durée pendant laquelle un backend dont la connexion vient d'échouer est écarté.
	passiveDownTTL = 10 * time.Second
	// maxDialAttempts : backends essayés pour une même connexion TCP avant d'abandonner.
	maxDialAttempts = 3

	defaultProbeInterval = 10 * time.Second
	defaultProbeTimeout  = 3 * time.Second
)

// pool répartit les connexions (TCP) et les sessions (UDP) d'une route L4 entre ses backends, en écartant ceux qui
// ne répondent pas : passivement (une connexion qui échoue écarte le backend quelques secondes) et, pour TCP quand la
// route définit health_check, par sondes de connexion périodiques. Un L4 n'a pas de requête à rejouer : seule la
// connexion initiale peut être retentée sur un autre backend.
type pool struct {
	route *router.Route

	mu    sync.Mutex
	turn  uint64
	state map[string]*backendState
}

type backendState struct {
	downUntil time.Time // écartement passif
	probeDown bool      // écarté par les sondes
	failures  int       // échecs de sonde consécutifs
	successes int       // succès de sonde consécutifs (pour revenir)
}

func newPool(route *router.Route) *pool {
	return &pool{route: route, state: map[string]*backendState{}}
}

func (p *pool) st(url string) *backendState {
	s := p.state[url]
	if s == nil {
		s = &backendState{}
		p.state[url] = s
	}
	return s
}

func (p *pool) healthy(url string, now time.Time) bool {
	s := p.st(url)
	return !s.probeDown && now.After(s.downUntil)
}

func weightOf(b router.Backend) int {
	if b.Weight > 0 {
		return b.Weight
	}
	return 1
}

// order retourne les backends dans l'ordre où les essayer : ceux qui sont sains, en tournant d'un appel à l'autre
// (pondéré si la route est « weighted »), puis les écartés — mieux vaut tenter un backend douteux qu'aucun, la
// panne de tous les backends à la fois étant plus probablement une panne de sonde.
func (p *pool) order() []*router.Backend {
	bs := p.route.Backends
	if len(bs) == 0 {
		return nil
	}
	now := time.Now()
	p.mu.Lock()
	defer p.mu.Unlock()
	var healthy, down []*router.Backend
	for i := range bs {
		if p.healthy(bs[i].URL, now) {
			healthy = append(healthy, &bs[i])
		} else {
			down = append(down, &bs[i])
		}
	}
	turn := p.turn
	p.turn++
	if p.route.LB == router.LBWeighted && len(healthy) > 1 {
		total := 0
		for _, b := range healthy {
			total += weightOf(*b)
		}
		n := int(turn % uint64(total))
		for i, b := range healthy {
			if n < weightOf(*b) {
				healthy[0], healthy[i] = healthy[i], healthy[0]
				break
			}
			n -= weightOf(*b)
		}
	} else if len(healthy) > 1 {
		k := int(turn % uint64(len(healthy)))
		healthy = append(append([]*router.Backend{}, healthy[k:]...), healthy[:k]...)
	}
	return append(healthy, down...)
}

// pick retourne le backend à utiliser, ou nil si la route n'en a aucun.
func (p *pool) pick() *router.Backend {
	if o := p.order(); len(o) > 0 {
		return o[0]
	}
	return nil
}

// markDown écarte un backend dont une connexion vient d'échouer.
func (p *pool) markDown(url string) {
	p.mu.Lock()
	p.st(url).downUntil = time.Now().Add(passiveDownTTL)
	p.mu.Unlock()
}

// markUp le rétablit (une connexion a abouti).
func (p *pool) markUp(url string) {
	p.mu.Lock()
	s := p.st(url)
	s.downUntil = time.Time{}
	p.mu.Unlock()
}

// dialTCP ouvre une connexion vers le premier backend qui répond, en en essayant au plus maxDialAttempts.
func (p *pool) dialTCP(timeout time.Duration) (net.Conn, *router.Backend, error) {
	var lastErr error
	for i, b := range p.order() {
		if i >= maxDialAttempts {
			break
		}
		c, err := net.DialTimeout("tcp", b.URL, timeout)
		if err == nil {
			p.markUp(b.URL)
			return c, b, nil
		}
		lastErr = err
		p.markDown(b.URL)
	}
	if lastErr == nil {
		lastErr = net.ErrClosed
	}
	return nil, nil, lastErr
}

// probe sonde en boucle les backends TCP jusqu'à l'annulation de ctx. UnhealthyThreshold échecs consécutifs écartent
// un backend, HealthyThreshold succès consécutifs le rétablissent (1 par défaut).
func (p *pool) probe(ctx context.Context, cfg *router.HealthCheckConfig) {
	interval, timeout := defaultProbeInterval, defaultProbeTimeout
	unhealthy, healthy := 1, 1
	if cfg.Interval > 0 {
		interval = cfg.Interval
	}
	if cfg.Timeout > 0 {
		timeout = cfg.Timeout
	}
	if cfg.UnhealthyThreshold > 0 {
		unhealthy = cfg.UnhealthyThreshold
	}
	if cfg.HealthyThreshold > 0 {
		healthy = cfg.HealthyThreshold
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		for _, b := range p.route.Backends {
			ok := false
			if c, err := net.DialTimeout("tcp", b.URL, timeout); err == nil {
				c.Close()
				ok = true
			}
			p.recordProbe(b.URL, ok, unhealthy, healthy)
		}
		select {
		case <-ctx.Done():
			return
		case <-t.C:
		}
	}
}

func (p *pool) recordProbe(url string, ok bool, unhealthy, healthy int) {
	p.mu.Lock()
	defer p.mu.Unlock()
	s := p.st(url)
	if ok {
		s.failures = 0
		s.successes++
		if s.probeDown && s.successes >= healthy {
			s.probeDown = false
		}
		return
	}
	s.successes = 0
	s.failures++
	if s.failures >= unhealthy {
		s.probeDown = true
	}
}
