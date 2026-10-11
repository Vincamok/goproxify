// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net"
	"net/http"
	"strings"
	"sync"
	"time"
)

const (
	loginMaxFails   = 5
	loginWindowSecs = 5 * time.Minute
	loginLockSecs   = 15 * time.Minute
)

type loginBucket struct {
	fails       int
	windowAt    time.Time
	lockedUntil time.Time
}

// loginLimiter limite les tentatives de login Admin par IP+email (mémoire process).
type loginLimiter struct {
	mu    sync.Mutex
	byKey map[string]*loginBucket
}

func newLoginLimiter() *loginLimiter {
	return &loginLimiter{byKey: map[string]*loginBucket{}}
}

// loginMaxFailsPerAccount : échecs, toutes adresses confondues, qui verrouillent un compte. Le plafond par adresse
// seul se contourne en changeant d'adresse (ou d'en-tête) à chaque requête.
const loginMaxFailsPerAccount = 10

// pairMaxFails : secrets d'appairage faux, depuis une même adresse, qui la verrouillent.
const pairMaxFails = 20

func accountKey(email string) string { return "account|" + strings.ToLower(strings.TrimSpace(email)) }

func loginKey(ip, email string) string {
	return strings.ToLower(strings.TrimSpace(ip)) + "|" + strings.ToLower(strings.TrimSpace(email))
}

// limiterIP : l'adresse qui sert de clé aux limiteurs. En-têtes de proxy ignorés sauf si la connexion vient d'une
// adresse privée ou locale (un proxy ou une passerelle devant l'Admin) ; on retient alors la **dernière** entrée de
// X-Forwarded-For, celle que le proxy de confiance a ajoutée — la première est écrite par le client et se choisit
// librement, ce qui rendait le limiteur de connexion contournable en la changeant à chaque requête.
func limiterIP(r *http.Request) string {
	remote := clientIP(r.RemoteAddr)
	ip := net.ParseIP(remote)
	if ip == nil || !(ip.IsLoopback() || ip.IsPrivate() || ip.IsLinkLocalUnicast()) {
		return remote
	}
	if xf := r.Header.Get("X-Forwarded-For"); xf != "" {
		parts := strings.Split(xf, ",")
		if last := strings.TrimSpace(parts[len(parts)-1]); net.ParseIP(last) != nil {
			return last
		}
	}
	return remote
}

func clientIP(rRemote string) string {
	host, _, err := net.SplitHostPort(rRemote)
	if err != nil {
		return rRemote
	}
	return host
}

func (l *loginLimiter) blocked(keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, key := range keys {
		b := l.byKey[key]
		if b == nil {
			continue
		}
		if now.Before(b.lockedUntil) {
			if d := b.lockedUntil.Sub(now); d > wait {
				wait = d
			}
			continue
		}
		if now.Sub(b.windowAt) > loginWindowSecs {
			b.fails = 0
			b.windowAt = now
		}
	}
	return wait > 0, wait
}

func (l *loginLimiter) fail(key string) { l.failN(key, loginMaxFails) }

// maxLimiterKeys borne la table : une clé par couple adresse + compte, qu'un client qui change d'adresse (ou
// d'en-tête) à chaque requête remplirait sans fin.
const maxLimiterKeys = 50000

// failN enregistre un échec ; au bout de max échecs dans la fenêtre, la clé est verrouillée.
func (l *loginLimiter) failN(key string, max int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.byKey) > maxLimiterKeys {
		for k, b := range l.byKey {
			if now.After(b.lockedUntil) && now.Sub(b.windowAt) > loginWindowSecs {
				delete(l.byKey, k)
			}
		}
	}
	b := l.byKey[key]
	if b == nil {
		b = &loginBucket{windowAt: now}
		l.byKey[key] = b
	}
	if now.Sub(b.windowAt) > loginWindowSecs {
		b.fails = 0
		b.windowAt = now
	}
	b.fails++
	if b.fails >= max {
		b.lockedUntil = now.Add(loginLockSecs)
		b.fails = 0
		b.windowAt = now
	}
}

func (l *loginLimiter) success(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, key := range keys {
		delete(l.byKey, key)
	}
}
