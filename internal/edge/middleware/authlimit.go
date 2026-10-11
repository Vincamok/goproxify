// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"

	"golang.org/x/crypto/bcrypt"
)

// Les authentifications par identifiants saisis dans le navigateur (Basic, LDAP) n'avaient aucune limite : un client
// essayait des mots de passe sans fin à travers la passerelle — et, pour LDAP, verrouillait les comptes de l'annuaire
// ou le saturait de requêtes de liaison. Le limiteur compte les échecs par couple adresse + identifiant (5 en
// 5 minutes) et par identifiant seul, toutes adresses confondues (20) ; au-delà, 429 pendant 15 minutes.
const (
	authFailPerClient = 5
	authFailPerUser   = 20
	authFailWindow    = 5 * time.Minute
	authLockout       = 15 * time.Minute
	authMaxKeys       = 50000
)

type authBucket struct {
	fails       int
	windowStart time.Time
	lockedUntil time.Time
}

type AuthFailLimiter struct {
	mu sync.Mutex
	m  map[string]*authBucket
}

func NewAuthFailLimiter() *AuthFailLimiter { return &AuthFailLimiter{m: map[string]*authBucket{}} }

// authClientIP : l'adresse de la connexion. Les en-têtes de proxy ne sont pas lus : un client les choisit, et changer
// d'en-tête à chaque essai rendrait le limiteur inopérant.
func authClientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func clientKey(ip, user string) string { return "c|" + ip + "|" + strings.ToLower(user) }
func userOnlyKey(user string) string   { return "u|" + strings.ToLower(user) }

func (l *AuthFailLimiter) blocked(keys ...string) (bool, time.Duration) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	var wait time.Duration
	for _, k := range keys {
		if b := l.m[k]; b != nil && now.Before(b.lockedUntil) {
			if d := b.lockedUntil.Sub(now); d > wait {
				wait = d
			}
		}
	}
	return wait > 0, wait
}

func (l *AuthFailLimiter) fail(key string, max int) {
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	if len(l.m) > authMaxKeys {
		for k, b := range l.m {
			if now.After(b.lockedUntil) && now.Sub(b.windowStart) > authFailWindow {
				delete(l.m, k)
			}
		}
	}
	b := l.m[key]
	if b == nil {
		b = &authBucket{windowStart: now}
		l.m[key] = b
	}
	if now.Sub(b.windowStart) > authFailWindow && now.After(b.lockedUntil) {
		b.fails, b.windowStart = 0, now
	}
	b.fails++
	if b.fails >= max {
		b.lockedUntil = now.Add(authLockout)
	}
}

func (l *AuthFailLimiter) success(keys ...string) {
	l.mu.Lock()
	defer l.mu.Unlock()
	for _, k := range keys {
		delete(l.m, k)
	}
}

// Guard retourne true si la requête peut être tentée ; sinon la réponse 429 est déjà écrite.
func (l *AuthFailLimiter) Guard(w http.ResponseWriter, r *http.Request, user string) bool {
	if blocked, wait := l.blocked(clientKey(authClientIP(r), user), userOnlyKey(user)); blocked {
		w.Header().Set("Retry-After", strconv.Itoa(int(wait.Seconds())+1))
		http.Error(w, "trop de tentatives — réessayez plus tard", http.StatusTooManyRequests)
		return false
	}
	return true
}

func (l *AuthFailLimiter) RecordFail(r *http.Request, user string) {
	l.fail(clientKey(authClientIP(r), user), authFailPerClient)
	l.fail(userOnlyKey(user), authFailPerUser)
}

func (l *AuthFailLimiter) RecordSuccess(r *http.Request, user string) {
	l.success(clientKey(authClientIP(r), user))
}

// dummyBcrypt sert à dépenser le même temps pour un identifiant inconnu que pour un mot de passe faux : sans lui, la
// vérification bcrypt n'avait lieu que pour les identifiants qui existent, et la durée de la réponse les révélait.
var (
	dummyOnce sync.Once
	dummyHash string
)

// SpendBcryptTime dépense le temps d'une vérification de mot de passe (voir ci-dessus).
func SpendBcryptTime(password string) {
	dummyOnce.Do(func() {
		h, _ := bcrypt.GenerateFromPassword([]byte("gpx-dummy-password"), bcrypt.DefaultCost)
		dummyHash = string(h)
	})
	_ = bcrypt.CompareHashAndPassword([]byte(dummyHash), []byte(password))
}
