// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"crypto/tls"
	"errors"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// probeConfig regroupe les paramètres d'une sonde par URL.
type probeConfig struct {
	path               string
	interval           time.Duration
	timeout            time.Duration
	healthyThreshold   int
	unhealthyThreshold int
}

func defaultProbeConfig() probeConfig {
	return probeConfig{
		path:               "/health",
		interval:           30 * time.Second,
		timeout:            5 * time.Second,
		healthyThreshold:   1,
		unhealthyThreshold: 1,
	}
}

func probeConfigFrom(cfg *router.HealthCheckConfig) probeConfig {
	p := defaultProbeConfig()
	if cfg == nil {
		return p
	}
	if cfg.Path != "" {
		p.path = cfg.Path
	}
	if cfg.Interval > 0 {
		p.interval = cfg.Interval
	}
	if cfg.Timeout > 0 {
		p.timeout = cfg.Timeout
	}
	if cfg.HealthyThreshold > 0 {
		p.healthyThreshold = cfg.HealthyThreshold
	}
	if cfg.UnhealthyThreshold > 0 {
		p.unhealthyThreshold = cfg.UnhealthyThreshold
	}
	return p
}

// backendState suit l'état de santé d'un backend avec compteurs de seuil.
type backendState struct {
	healthy    bool
	downUntil  time.Time
	streak     int  // succès consécutifs (>0) ou échecs consécutifs (<0)
	upSince    time.Time // dernier passage en service (création, reprise après panne) : base du slow-start
	cfg        probeConfig
}

// watcher est la sonde active d'un backend : sa config et le canal qui l'arrête.
type watcher struct {
	cfg  probeConfig
	stop chan struct{}
}

// BackendHealth suit l'état de santé d'un backend par URL.
type BackendHealth struct {
	mu      sync.RWMutex
	states  map[string]*backendState
	watched map[string]watcher // URLs avec une goroutine de check active
	log     *slog.Logger
	OnDown  func(url string) // appelé quand un backend passe healthy→unhealthy
}

func NewBackendHealth(log *slog.Logger) *BackendHealth {
	return &BackendHealth{
		states:  make(map[string]*backendState),
		watched: make(map[string]watcher),
		log:     log,
	}
}

// IsHealthy retourne true si le backend est considéré en bonne santé.
// Un backend inconnu est considéré sain par défaut.
func (h *BackendHealth) IsHealthy(u string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	st, ok := h.states[u]
	if !ok {
		return true
	}
	if time.Now().Before(st.downUntil) {
		return false
	}
	return st.healthy
}

// MarkDown place le backend en quarantaine temporaire (failover immédiat).
func (h *BackendHealth) MarkDown(u string, ttl time.Duration) {
	if h == nil || u == "" {
		return
	}
	if ttl <= 0 {
		ttl = 15 * time.Second
	}
	h.mu.Lock()
	st := h.getOrCreateLocked(u)
	st.downUntil = time.Now().Add(ttl)
	h.mu.Unlock()
	metrics.BackendUp.WithLabelValues(u).Set(0)
	if h.log != nil {
		h.log.Info("backend quarantine", "url", u, "ttl", ttl.String())
	}
}

// MarkUp lève la quarantaine après un succès.
func (h *BackendHealth) MarkUp(u string) {
	if h == nil || u == "" {
		return
	}
	h.mu.Lock()
	st := h.getOrCreateLocked(u)
	if !st.healthy || !st.downUntil.IsZero() {
		st.upSince = time.Now()
	}
	st.downUntil = time.Time{}
	st.healthy = true
	h.mu.Unlock()
	metrics.BackendUp.WithLabelValues(u).Set(1)
}

// slowStartFloor : part minimale de trafic d'un backend qui vient d'entrer en service,
// pour qu'il reçoive de vrais échanges dès la première seconde.
const slowStartFloor = 0.05

// RampFactor retourne la part de trafic nominale [slowStartFloor, 1] d'un backend
// pendant sa montée en charge ; 1 hors fenêtre, sans fenêtre ou pour un backend inconnu.
func (h *BackendHealth) RampFactor(u string, window time.Duration) float64 {
	if h == nil || window <= 0 {
		return 1
	}
	h.mu.RLock()
	st, ok := h.states[u]
	var since time.Time
	if ok {
		since = st.upSince
	}
	h.mu.RUnlock()
	if since.IsZero() {
		return 1
	}
	elapsed := time.Since(since)
	if elapsed >= window {
		return 1
	}
	return slowStartFloor + (1-slowStartFloor)*float64(elapsed)/float64(window)
}

// Status retourne "up", "down" ou "unknown" pour une URL backend.
func (h *BackendHealth) Status(u string) string {
	if h == nil || u == "" {
		return "unknown"
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	st, ok := h.states[u]
	if !ok {
		return "unknown"
	}
	if time.Now().Before(st.downUntil) {
		return "down"
	}
	if st.healthy {
		return "up"
	}
	return "down"
}

// Snapshot retourne le statut connu de chaque backend (url → up|down|unknown).
func (h *BackendHealth) Snapshot() map[string]string {
	out := make(map[string]string)
	if h == nil {
		return out
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	now := time.Now()
	for u, st := range h.states {
		if now.Before(st.downUntil) {
			out[u] = "down"
			continue
		}
		if st.healthy {
			out[u] = "up"
		} else {
			out[u] = "down"
		}
	}
	return out
}

func (h *BackendHealth) getOrCreateLocked(u string) *backendState {
	if st, ok := h.states[u]; ok {
		return st
	}
	st := &backendState{healthy: true, cfg: defaultProbeConfig(), upSince: time.Now()}
	h.states[u] = st
	return st
}

// quarantineDuration retourne la durée de quarantaine adaptée au type d'erreur.
func quarantineDuration(err error) time.Duration {
	if err == nil {
		return 15 * time.Second
	}
	var ue *url.Error
	if errors.As(err, &ue) {
		err = ue.Err
	}
	var ne *net.OpError
	if errors.As(err, &ne) {
		if ne.Temporary() {
			return 0
		}
		if errors.Is(ne.Err, syscall.ECONNRESET) || errors.Is(ne.Err, syscall.EPIPE) {
			return 0
		}
		if errors.Is(ne.Err, syscall.ECONNREFUSED) {
			return 15 * time.Second
		}
	}
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return 0
	}
	return 15 * time.Second
}

// StartChecks lance les health checks actifs avec la config par défaut.
// Idempotent : les URLs déjà surveillées ne lancent pas de nouvelle goroutine.
func (h *BackendHealth) StartChecks(urls []string, interval time.Duration) {
	cfg := defaultProbeConfig()
	if interval > 0 {
		cfg.interval = interval
	}
	h.mu.Lock()
	for _, u := range urls {
		if u != "" {
			h.startLocked(u, cfg)
		}
	}
	h.mu.Unlock()
}

// moreSpecific indique si a doit remplacer b comme config de sonde d'un backend partagé :
// une config explicite l'emporte sur le défaut, puis l'intervalle le plus court
// (le plus réactif), puis l'ordre alphabétique du chemin pour rester déterministe.
func moreSpecific(a, b probeConfig, aExplicit, bExplicit bool) bool {
	if aExplicit != bExplicit {
		return aExplicit
	}
	if a.interval != b.interval {
		return a.interval < b.interval
	}
	return a.path < b.path
}

// Sync réconcilie les sondes avec l'ensemble de routes donné : démarre celles des nouveaux
// backends, relance celles dont la config a changé, arrête celles des backends disparus.
// Lorsque plusieurs routes partagent un backend, la config la plus spécifique est retenue.
// Idempotent et peu coûteux : à appeler après toute modification de la table.
func (h *BackendHealth) Sync(routes []*router.Route) {
	if h == nil {
		return
	}
	type want struct {
		cfg      probeConfig
		explicit bool
	}
	desired := make(map[string]want)
	for _, r := range routes {
		if r == nil || r.Type == router.RouteUDP {
			continue
		}
		pc := probeConfigFrom(r.HealthCheck)
		explicit := r.HealthCheck != nil
		for _, b := range r.Backends {
			if b.URL == "" {
				continue
			}
			if cur, ok := desired[b.URL]; !ok || moreSpecific(pc, cur.cfg, explicit, cur.explicit) {
				desired[b.URL] = want{pc, explicit}
			}
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for u, w := range desired {
		h.startLocked(u, w.cfg)
	}
	for u, p := range h.watched {
		if _, ok := desired[u]; !ok {
			close(p.stop)
			delete(h.watched, u)
			delete(h.states, u)
		}
	}
}

// startLocked démarre (ou relance si la config diffère) la sonde de u. h.mu doit être tenu.
func (h *BackendHealth) startLocked(u string, cfg probeConfig) {
	if p, ok := h.watched[u]; ok {
		if p.cfg == cfg {
			return
		}
		close(p.stop)
	}
	stop := make(chan struct{})
	h.watched[u] = watcher{cfg: cfg, stop: stop}
	h.getOrCreateLocked(u).cfg = cfg
	go h.loop(u, cfg, stop)
}

func (h *BackendHealth) loop(target string, cfg probeConfig, stop <-chan struct{}) {
	for {
		ok := probeWithConfig(target, cfg)
		select {
		case <-stop:
			return
		default:
		}
		h.mu.Lock()
		st := h.getOrCreateLocked(target)
		prevHealthy := st.healthy
		if ok {
			if st.streak < 0 {
				st.streak = 0
			}
			st.streak++
			if st.streak >= cfg.healthyThreshold {
				if !st.healthy || !st.downUntil.IsZero() {
					st.upSince = time.Now()
				}
				st.healthy = true
				st.downUntil = time.Time{}
			}
		} else {
			if st.streak > 0 {
				st.streak = 0
			}
			st.streak--
			if -st.streak >= cfg.unhealthyThreshold {
				st.healthy = false
			}
		}
		wentDown := prevHealthy && !st.healthy
		changed := prevHealthy != st.healthy
		h.mu.Unlock()
		if changed && h.log != nil {
			h.log.Info("backend health change", "url", target, "healthy", ok)
		}
		if wentDown && h.OnDown != nil {
			h.OnDown(target)
		}
		select {
		case <-stop:
			return
		case <-time.After(cfg.interval):
		}
	}
}

// probeClient ne vérifie pas le certificat backend : la sonde teste la vivacité,
// pas l'authenticité.
var probeClient = &http.Client{
	Timeout: 5 * time.Second,
	Transport: &http.Transport{
		TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		DisableKeepAlives: true,
	},
	CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
}

const probeTimeout = 5 * time.Second

// probeWithConfig teste la vivacité d'un backend avec une config personnalisée.
func probeWithConfig(target string, cfg probeConfig) bool {
	u, err := url.Parse(target)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") {
		return tcpReachable(target, cfg.timeout)
	}
	client := probeClient
	if cfg.timeout != probeTimeout {
		client = &http.Client{
			Timeout: cfg.timeout,
			Transport: &http.Transport{
				TLSClientConfig:   &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
				DisableKeepAlives: true,
			},
			CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		}
	}
	path := cfg.path
	if path == "" {
		path = "/health"
	}
	resp, err := client.Get(strings.TrimSuffix(target, "/") + path)
	if err != nil {
		return tcpReachable(hostPort(u), cfg.timeout)
	}
	io.Copy(io.Discard, io.LimitReader(resp.Body, 4<<10)) //nolint:errcheck
	resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return false
	}
	return true
}

// probe est l'API de compatibilité utilisée dans les tests.
func probe(target string) bool {
	return probeWithConfig(target, defaultProbeConfig())
}

func tcpReachable(addr string, timeout time.Duration) bool {
	if addr == "" {
		return false
	}
	if timeout <= 0 {
		timeout = probeTimeout
	}
	conn, err := net.DialTimeout("tcp", addr, timeout)
	if err != nil {
		return false
	}
	conn.Close()
	return true
}

// hostPort retourne l'adresse dialable d'une URL, en complétant le port implicite.
func hostPort(u *url.URL) string {
	if u.Port() != "" {
		return u.Host
	}
	if u.Scheme == "https" {
		return net.JoinHostPort(u.Hostname(), "443")
	}
	return net.JoinHostPort(u.Hostname(), "80")
}
