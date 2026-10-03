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

// backendState suit l'état passif d'un backend par URL (quarantaine, slow-start).
type backendState struct {
	healthy   bool
	downUntil time.Time
	upSince   time.Time // dernier passage en service (création, reprise après panne) : base du slow-start
}

// probeKey identifie une sonde active : chaque route sonde ses backends avec sa propre config.
type probeKey struct{ route, url string }

// probeState est la sonde active d'une route sur un backend : config, état et canal d'arrêt.
type probeState struct {
	cfg     probeConfig
	stop    chan struct{}
	healthy bool
	streak  int // succès consécutifs (>0) ou échecs consécutifs (<0)
}

// BackendHealth suit l'état de santé des backends : état passif par URL (quarantaine sur erreur
// de proxy) et sondes actives par couple (route, URL).
type BackendHealth struct {
	mu     sync.RWMutex
	states map[string]*backendState
	probes map[probeKey]*probeState
	log    *slog.Logger
	OnDown func(url string) // appelé quand un backend passe healthy→unhealthy pour une route
}

func NewBackendHealth(log *slog.Logger) *BackendHealth {
	return &BackendHealth{
		states: make(map[string]*backendState),
		probes: make(map[probeKey]*probeState),
		log:    log,
	}
}

// IsHealthy retourne true si le backend est considéré en bonne santé, toutes routes confondues
// (aucune sonde active ne le juge malsain). Un backend inconnu est considéré sain par défaut.
func (h *BackendHealth) IsHealthy(u string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	return h.passiveUpLocked(u) && !h.anyProbeDownLocked(u)
}

// IsHealthyFor est IsHealthy du point de vue d'une route : quarantaine passive de l'URL et
// verdict de la sonde propre à cette route (ses seuils, son chemin).
func (h *BackendHealth) IsHealthyFor(route, u string) bool {
	h.mu.RLock()
	defer h.mu.RUnlock()
	if !h.passiveUpLocked(u) {
		return false
	}
	if p, ok := h.probes[probeKey{route, u}]; ok {
		return p.healthy
	}
	return true
}

func (h *BackendHealth) passiveUpLocked(u string) bool {
	st, ok := h.states[u]
	return !ok || (st.healthy && !time.Now().Before(st.downUntil))
}

func (h *BackendHealth) anyProbeDownLocked(u string) bool {
	for k, p := range h.probes {
		if k.url == u && !p.healthy {
			return true
		}
	}
	return false
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
	if _, ok := h.states[u]; !ok {
		return "unknown"
	}
	if h.passiveUpLocked(u) && !h.anyProbeDownLocked(u) {
		return "up"
	}
	return "down"
}

// Snapshot retourne le statut connu de chaque backend (url → up|down).
func (h *BackendHealth) Snapshot() map[string]string {
	out := make(map[string]string)
	if h == nil {
		return out
	}
	h.mu.RLock()
	defer h.mu.RUnlock()
	for u := range h.states {
		out[u] = "up"
		if !h.passiveUpLocked(u) {
			out[u] = "down"
		}
	}
	for k, p := range h.probes {
		if !p.healthy {
			out[k.url] = "down"
		}
	}
	return out
}

func (h *BackendHealth) getOrCreateLocked(u string) *backendState {
	if st, ok := h.states[u]; ok {
		return st
	}
	st := &backendState{healthy: true, upSince: time.Now()}
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

// StartChecks lance les health checks actifs avec la config par défaut (sans route associée).
// Idempotent : les URLs déjà surveillées ne lancent pas de nouvelle goroutine.
func (h *BackendHealth) StartChecks(urls []string, interval time.Duration) {
	cfg := defaultProbeConfig()
	if interval > 0 {
		cfg.interval = interval
	}
	h.mu.Lock()
	for _, u := range urls {
		if u != "" {
			h.startLocked(probeKey{url: u}, cfg)
		}
	}
	h.mu.Unlock()
}

// Sync réconcilie les sondes avec l'ensemble de routes donné : une sonde par (route, backend),
// avec le health_check de la route. Démarre celles des nouvelles routes, relance celles dont la
// config a changé, arrête celles des routes ou backends disparus. Idempotent et peu coûteux :
// à appeler après toute modification de la table.
func (h *BackendHealth) Sync(routes []*router.Route) {
	if h == nil {
		return
	}
	desired := make(map[probeKey]probeConfig)
	for _, r := range routes {
		if r == nil || r.Type == router.RouteUDP {
			continue
		}
		pc := probeConfigFrom(r.HealthCheck)
		for _, b := range r.Backends {
			if b.URL != "" {
				desired[probeKey{r.ID, b.URL}] = pc
			}
		}
	}
	h.mu.Lock()
	defer h.mu.Unlock()
	for k, cfg := range desired {
		h.startLocked(k, cfg)
	}
	for k, p := range h.probes {
		if _, ok := desired[k]; !ok {
			close(p.stop)
			delete(h.probes, k)
		}
	}
	for u := range h.states {
		used := false
		for k := range h.probes {
			if k.url == u {
				used = true
				break
			}
		}
		if !used {
			delete(h.states, u)
		}
	}
}

// startLocked démarre (ou relance si la config diffère) la sonde k. h.mu doit être tenu.
// Une sonde relancée garde son verdict courant jusqu'à sa première mesure.
func (h *BackendHealth) startLocked(k probeKey, cfg probeConfig) {
	p, ok := h.probes[k]
	if ok {
		if p.cfg == cfg {
			return
		}
		close(p.stop)
	} else {
		p = &probeState{healthy: true}
		h.probes[k] = p
	}
	p.cfg = cfg
	p.stop = make(chan struct{})
	h.getOrCreateLocked(k.url)
	go h.loop(k, p, cfg, p.stop)
}

func (h *BackendHealth) loop(k probeKey, p *probeState, cfg probeConfig, stop <-chan struct{}) {
	for {
		ok := probeWithConfig(k.url, cfg)
		select {
		case <-stop:
			return
		default:
		}
		h.mu.Lock()
		prevHealthy := p.healthy
		if ok {
			if p.streak < 0 {
				p.streak = 0
			}
			p.streak++
			if p.streak >= cfg.healthyThreshold {
				p.healthy = true
				if st := h.states[k.url]; st != nil {
					if !prevHealthy || !st.healthy || !st.downUntil.IsZero() {
						st.upSince = time.Now()
					}
					st.healthy = true
					st.downUntil = time.Time{}
				}
			}
		} else {
			if p.streak > 0 {
				p.streak = 0
			}
			p.streak--
			if -p.streak >= cfg.unhealthyThreshold {
				p.healthy = false
			}
		}
		wentDown := prevHealthy && !p.healthy
		changed := prevHealthy != p.healthy
		h.mu.Unlock()
		if changed && h.log != nil {
			h.log.Info("backend health change", "route", k.route, "url", k.url, "healthy", ok)
		}
		if wentDown && h.OnDown != nil {
			h.OnDown(k.url)
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
