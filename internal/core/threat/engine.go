// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package threat implémente le moteur de détection automatique des menaces du Core.
// Il est indépendant des bans manuels (natifs) et s'active/désactive à chaud.
package threat

import (
	"context"
	"log/slog"
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

// Name est l'identifiant affiché dans les logs pour ce moteur.
const Name = "Sentinel"

// BanCallback est appelé quand le moteur détecte une menace et doit bannir une IP.
// Le caller (server.go) ajoute le ban au BanStore et le notifie à Admin.
type BanCallback func(ip, reason string, expires time.Time)

// Engine est le moteur de détection. Un seul par Core, démarré via Start().
type Engine struct {
	mu  sync.RWMutex
	cfg Config

	lists    *Lists
	counters *counterStore
	wl       *whitelist

	banFn BanCallback
	log   *slog.Logger

	cancel context.CancelFunc
	done   chan struct{}
}

// New crée un moteur de détection (non démarré).
func New(log *slog.Logger, banFn BanCallback) *Engine {
	return &Engine{
		lists:    newLists(log),
		counters: newCounterStore(),
		log:      log,
		banFn:    banFn,
		done:     make(chan struct{}),
	}
}

// Start démarre la boucle de refresh des listes. Doit être appelé une seule fois.
// Les fichiers de listes par défaut sont toujours seedés dans le volume au démarrage,
// même si le moteur n'est pas encore activé, afin que l'utilisateur puisse les éditer.
func (e *Engine) Start(ctx context.Context) {
	e.lists.seedDefaults()
	ctx, cancel := context.WithCancel(ctx)
	e.cancel = cancel
	go e.run(ctx)
}

// Stop arrête proprement le moteur.
func (e *Engine) Stop() {
	if e.cancel != nil {
		e.cancel()
	}
	<-e.done
}

// UpdateConfig remplace la config à chaud.
func (e *Engine) UpdateConfig(cfg Config) {
	cfg.defaults()
	e.mu.Lock()
	e.cfg = cfg
	e.wl = buildWhitelist(cfg.Whitelist)
	e.mu.Unlock()

	// Charger depuis le disque si le moteur vient d'être activé.
	if cfg.Enabled {
		e.lists.loadFromDisk(cfg.Lists)
	}
}

// Enabled retourne vrai si le moteur est actif.
func (e *Engine) Enabled() bool {
	e.mu.RLock()
	defer e.mu.RUnlock()
	return e.cfg.Enabled
}

// Check analyse une requête entrante et retourne la raison si elle doit être bloquée.
// Doit être appelé avant d'acheminer la requête.
func (e *Engine) Check(r *http.Request, ip string) (blocked bool, reason string) {
	e.mu.RLock()
	cfg := e.cfg
	wl := e.wl
	e.mu.RUnlock()

	if !cfg.Enabled {
		return false, ""
	}
	if wl.allowedIP(ip) {
		return false, ""
	}

	ua := r.Header.Get("User-Agent")
	if wl.allowedUA(ua) {
		return false, ""
	}
	path := r.URL.Path
	if wl.allowedPath(path) {
		return false, ""
	}

	// 1. Liste IP.
	if cfg.Lists.IPEnabled && e.lists.MatchIP(ip) {
		return true, "threat: IP liste noire"
	}

	// 2. User-Agent.
	if cfg.Lists.UAEnabled && ua != "" && e.lists.MatchUA(ua) {
		return true, "threat: User-Agent malveillant"
	}

	// 3. Path suspect.
	if cfg.Lists.PathEnabled && e.lists.MatchPath(path) {
		return true, "threat: path suspect"
	}

	// 4. Rate limit.
	if cfg.RateLimit > 0 {
		if e.counters.rateExceeded(ip, cfg.RateLimit, cfg.RateWindow.Duration) {
			return true, "threat: rate limit"
		}
	}

	return false, ""
}

// RecordStatus doit être appelé après chaque réponse pour alimenter les compteurs 4xx.
func (e *Engine) RecordStatus(ip string, status int) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()

	if !cfg.Enabled || cfg.ErrorThreshold <= 0 {
		return
	}
	if status < 400 || status >= 500 {
		return
	}

	if e.counters.errorExceeded(ip, cfg.ErrorThreshold, cfg.ErrorWindow.Duration) {
		expires := time.Now().Add(cfg.BanDuration.Duration)
		e.log.Warn("threat: ban automatique 4xx", "ip", ip, "status", status)
		if e.banFn != nil {
			e.banFn(ip, "threat: erreurs 4xx répétées", expires)
		}
		e.counters.resetErrors(ip)
	}
}

// ApplyHAPayload applique les listes reçues d'un peer HA.
func (e *Engine) ApplyHAPayload(p HAPayload) {
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	e.lists.ApplyHAPayload(p, cfg.Lists)
}

// BuildHAPayload construit le payload pour un peer HA.
func (e *Engine) BuildHAPayload() HAPayload {
	return e.lists.BuildHAPayload()
}

func (e *Engine) run(ctx context.Context) {
	defer close(e.done)

	// Premier refresh immédiat si activé.
	e.mu.RLock()
	cfg := e.cfg
	e.mu.RUnlock()
	if cfg.Enabled {
		e.lists.refresh(ctx, cfg.Lists)
	}

	for {
		e.mu.RLock()
		cfg = e.cfg
		e.mu.RUnlock()

		interval := cfg.Lists.RefreshInterval.Duration
		if interval <= 0 {
			interval = 6 * time.Hour
		}

		select {
		case <-ctx.Done():
			return
		case <-time.After(interval):
			e.mu.RLock()
			cfg = e.cfg
			e.mu.RUnlock()
			if cfg.Enabled {
				e.lists.refresh(ctx, cfg.Lists)
			}
		}
	}
}

// ── Whitelist ─────────────────────────────────────────────────────────────────

type whitelist struct {
	nets  []*net.IPNet
	ips   []net.IP
	uas   []string // sous-chaînes en minuscules
	paths []string // préfixes en minuscules
}

func buildWhitelist(wl Whitelist) *whitelist {
	w := &whitelist{}
	for _, s := range wl.IPs {
		if strings.Contains(s, "/") {
			if _, n, err := net.ParseCIDR(s); err == nil {
				w.nets = append(w.nets, n)
			}
		} else if ip := net.ParseIP(s); ip != nil {
			w.ips = append(w.ips, ip)
		}
	}
	for _, s := range wl.UAs {
		w.uas = append(w.uas, strings.ToLower(s))
	}
	for _, s := range wl.Paths {
		w.paths = append(w.paths, strings.ToLower(s))
	}
	return w
}

func (w *whitelist) allowedIP(ipStr string) bool {
	if w == nil {
		return false
	}
	ip := net.ParseIP(ipStr)
	if ip == nil {
		return false
	}
	for _, n := range w.nets {
		if n.Contains(ip) {
			return true
		}
	}
	for _, wip := range w.ips {
		if wip.Equal(ip) {
			return true
		}
	}
	return false
}

func (w *whitelist) allowedUA(ua string) bool {
	if w == nil || ua == "" {
		return false
	}
	uaLow := strings.ToLower(ua)
	for _, s := range w.uas {
		if strings.Contains(uaLow, s) {
			return true
		}
	}
	return false
}

func (w *whitelist) allowedPath(path string) bool {
	if w == nil {
		return false
	}
	pathLow := strings.ToLower(path)
	for _, p := range w.paths {
		if strings.HasPrefix(pathLow, p) {
			return true
		}
	}
	return false
}
