// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"
)

// Le mot de passe est protégé par le limiteur de connexion (5 échecs, 15 minutes de blocage) ; le second facteur
// ne l'était pas : avec le jeton « mfa_pending » que rend un mot de passe correct, un code TOTP à 6 chiffres ou un
// code de secours se devinait sans limite. Le limiteur ci-dessous compte les échecs par compte, quelle que soit
// l'adresse : une clé par adresse se contournerait en changeant d'IP. Contrepartie assumée : qui connaît le mot
// de passe peut verrouiller le second facteur du compte pendant 15 minutes (le login a la même propriété).
const (
	mfaMaxFailsPerUser = 5

	// Envois de codes (email, SMS, push) : chacun coûte (SMS facturé, boîte de la victime) et un compte authentifié,
	// quel que soit son rôle, peut les déclencher à volonté.
	sendMaxPerUser   = 3
	sendWindow       = 10 * time.Minute
	sendMaxGlobal    = 60
	sendGlobalWindow = time.Hour
	mfaWindow          = 15 * time.Minute
	mfaLockout         = 15 * time.Minute

	// totpReplayTTL couvre la fenêtre de validité d'un code TOTP (±1 pas de 30 s) : un code accepté ne sert qu'une fois.
	totpReplayTTL  = 100 * time.Second
	maxLimiterKeys = 10000
)

type mfaBucket struct {
	fails       int
	windowStart time.Time
	lockedUntil time.Time
}

// mfaLimiter est le limiteur de tentatives du second facteur (en mémoire du processus, comme celui de la connexion).
type mfaLimiter struct {
	mu      sync.Mutex
	buckets map[string]*mfaBucket
	used    map[string]time.Time // codes TOTP déjà acceptés : « utilisateur|code » → échéance
	sends   map[string]*sendWindowCount
}

func newMFALimiter() *mfaLimiter {
	return &mfaLimiter{buckets: map[string]*mfaBucket{}, used: map[string]time.Time{}}
}

func userKey(userID string) string { return "u:" + userID }

// setupKey sépare les échecs de vérification d'un nouveau facteur de ceux de la connexion : se tromper en activant un
// facteur ne doit pas verrouiller la connexion du compte.
func setupKey(userID string) string { return "s:" + userID }

var e164 = regexp.MustCompile(`^\+[1-9][0-9]{7,14}$`)

type sendWindowCount struct {
	start time.Time
	n     int
}

// allowSend compte un envoi de code : au plus sendMaxPerUser par compte et sendMaxGlobal au total par fenêtre.
// Un refus ne consomme rien.
func (l *mfaLimiter) allowSend(userID string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if l.sends == nil {
		l.sends = map[string]*sendWindowCount{}
	}
	if len(l.sends) > maxLimiterKeys {
		for k, c := range l.sends {
			if now.Sub(c.start) > sendGlobalWindow {
				delete(l.sends, k)
			}
		}
	}
	check := func(key string, max int, win time.Duration) (*sendWindowCount, time.Duration) {
		c := l.sends[key]
		if c == nil || now.Sub(c.start) > win {
			c = &sendWindowCount{start: now}
			l.sends[key] = c
		}
		if c.n >= max {
			return c, win - now.Sub(c.start)
		}
		return c, 0
	}
	u, wait := check("u:"+userID, sendMaxPerUser, sendWindow)
	g, gwait := check("global", sendMaxGlobal, sendGlobalWindow)
	if wait > 0 || gwait > 0 {
		if gwait > wait {
			wait = gwait
		}
		return false, wait
	}
	u.n++
	g.n++
	return true, 0
}

func (h *MFAHandler) allowSend(w http.ResponseWriter, userID string) bool {
	ok, wait := h.lim().allowSend(userID)
	if !ok {
		secs := int(wait.Seconds()) + 1
		w.Header().Set("Retry-After", strconv.Itoa(secs))
		http.Error(w, "trop d'envois de code : réessayez dans "+strconv.Itoa((secs+59)/60)+" min", http.StatusTooManyRequests)
	}
	return ok
}

func (h *MFAHandler) allowVerify(w http.ResponseWriter, userID string) bool {
	if blocked, wait := h.lim().blocked(setupKey(userID)); blocked {
		tooManyMFAAttempts(w, wait)
		return false
	}
	return true
}

// blocked indique si l'une des clés est verrouillée, et pour combien de temps.
func (l *mfaLimiter) blocked(keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		if b := l.buckets[k]; b != nil && now.Before(b.lockedUntil) {
			if d := b.lockedUntil.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait > 0, wait
}

// fail enregistre un échec sur chaque clé ; au-delà du seuil la clé est verrouillée.
func (l *mfaLimiter) fail(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.buckets) > maxLimiterKeys {
		l.prune(now)
	}
	for _, k := range keys {
		b := l.buckets[k]
		if b == nil {
			b = &mfaBucket{windowStart: now}
			l.buckets[k] = b
		}
		if now.Sub(b.windowStart) > mfaWindow && now.After(b.lockedUntil) {
			b.fails, b.windowStart = 0, now
		}
		b.fails++
		if b.fails >= mfaMaxFailsPerUser {
			b.lockedUntil = now.Add(mfaLockout)
		}
	}
}

// success efface les échecs de l'utilisateur (un second facteur réussi remet le compteur à zéro).
func (l *mfaLimiter) success(userID string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	delete(l.buckets, userKey(userID))
}

func (l *mfaLimiter) prune(now time.Time) {
	for k, b := range l.buckets {
		if now.After(b.lockedUntil) && now.Sub(b.windowStart) > mfaWindow {
			delete(l.buckets, k)
		}
	}
	for k, exp := range l.used {
		if now.After(exp) {
			delete(l.used, k)
		}
	}
}

// claimTOTP réserve un code TOTP accepté : false s'il a déjà servi dans sa fenêtre de validité (rejeu).
func (l *mfaLimiter) claimTOTP(userID, code string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.used) > maxLimiterKeys {
		l.prune(now)
	}
	key := userID + "|" + strings.TrimSpace(code)
	if exp, ok := l.used[key]; ok && now.Before(exp) {
		return false
	}
	l.used[key] = now.Add(totpReplayTTL)
	return true
}

// tooManyMFAAttempts répond 429 avec le délai restant.
func tooManyMFAAttempts(w http.ResponseWriter, wait time.Duration) {
	secs := int(wait.Seconds()) + 1
	w.Header().Set("Retry-After", strconv.Itoa(secs))
	http.Error(w, "trop de tentatives : réessayez dans "+strconv.Itoa((secs+59)/60)+" min", http.StatusTooManyRequests)
}
