// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth

import (
	"net/http"
	"strconv"
	"sync"
	"time"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
)

const (
	patMaxFails    = 10
	patFailWindow  = 5 * time.Minute
	patLockout     = 15 * time.Minute
	patMaxTracked  = 50000
	patLockedError = "trop d'échecs d'authentification — réessayez plus tard"
)

type patBucket struct {
	fails       int
	windowAt    time.Time
	lockedUntil time.Time
}

// patFailLimiter verrouille une adresse après patMaxFails jetons refusés dans patFailWindow. Pas de remise à zéro sur
// succès : un porteur de jeton valide ne doit pas pouvoir vider son compteur pour deviner les jetons des autres.
type patFailLimiter struct {
	mu    sync.Mutex
	byIP  map[string]*patBucket
	clock func() time.Time
}

func newPATFailLimiter() *patFailLimiter {
	return &patFailLimiter{byIP: map[string]*patBucket{}, clock: time.Now}
}

// blocked retourne le temps restant de verrouillage de ip, 0 si elle peut passer.
func (l *patFailLimiter) blocked(ip string) time.Duration {
	l.mu.Lock()
	defer l.mu.Unlock()
	if b := l.byIP[ip]; b != nil {
		if d := b.lockedUntil.Sub(l.clock()); d > 0 {
			return d
		}
	}
	return 0
}

// fail compte un échec ; vrai si cet échec verrouille l'adresse.
func (l *patFailLimiter) fail(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.clock()
	if len(l.byIP) > patMaxTracked {
		for k, b := range l.byIP {
			if now.After(b.lockedUntil) && now.Sub(b.windowAt) > patFailWindow {
				delete(l.byIP, k)
			}
		}
	}
	b := l.byIP[ip]
	if b == nil {
		b = &patBucket{windowAt: now}
		l.byIP[ip] = b
	}
	if now.Sub(b.windowAt) > patFailWindow {
		b.fails = 0
		b.windowAt = now
	}
	b.fails++
	if b.fails < patMaxFails {
		return false
	}
	b.lockedUntil = now.Add(patLockout)
	b.fails = 0
	b.windowAt = now
	return true
}

// PATOption règle RequirePAT.
type PATOption func(*patConfig)

type patConfig struct {
	limiter   *patFailLimiter
	allow     func(r *http.Request) bool
	onLockout func(r *http.Request, ip string)
}

// WithPATLockoutHook appelle fn quand une adresse vient d être verrouillée (journal d audit, alerte). L option porte son
// compteur : la passer à plusieurs RequirePAT (les chemins /mcp et /mcp/) leur fait partager le même budget d échecs.
func WithPATLockoutHook(fn func(r *http.Request, ip string)) PATOption {
	l := newPATFailLimiter()
	return func(c *patConfig) { c.onLockout, c.limiter = fn, l }
}

func (c *patConfig) rejectLocked(w http.ResponseWriter, wait time.Duration) {
	w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
	http.Error(w, patLockedError, http.StatusTooManyRequests)
}

func clientIPKey(r *http.Request) string { return edgelog.RealIP(r) }

// WithPATSourceGate refuse (403) un appelant que allow écarte, avant de regarder le jeton : ces requêtes ne touchent ni la
// base ni le compteur d'échecs.
func WithPATSourceGate(allow func(r *http.Request) bool) PATOption {
	return func(c *patConfig) { c.allow = allow }
}
