// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package logthrottle regroupe les lignes de journal qui se répètent pour une même clé.
package logthrottle

import (
	"sync"
	"time"
)

// MaxKeys borne la mémoire sous une attaque venue de très nombreuses adresses : au-delà, les lignes
// sont journalisées sans regroupement plutôt que de grossir la table.
const MaxKeys = 20000

// Limiter laisse passer une ligne de journal par clé et par fenêtre, et compte les lignes écartées entre
// deux passages. Un scanner qui insiste sur une IP déjà bannie produisait une ligne par requête (jusqu'à
// 12 000 pour une seule IP), soit plus de la moitié des logs de l'Admin.
type Limiter struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]*entry
	now    func() time.Time
}

type entry struct {
	last       time.Time
	suppressed int
}

// New crée un limiteur dont la fenêtre est la durée minimale entre deux lignes d'une même clé.
func New(window time.Duration) *Limiter {
	return &Limiter{window: window, seen: make(map[string]*entry), now: time.Now}
}

// Allow indique s'il faut journaliser cet événement et, si oui, combien d'événements identiques ont été
// écartés depuis la ligne précédente. Un limiteur nil journalise tout.
func (l *Limiter) Allow(key string) (log bool, suppressed int) {
	if l == nil {
		return true, 0
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	if e, ok := l.seen[key]; ok {
		if now.Sub(e.last) < l.window {
			e.suppressed++
			return false, 0
		}
		n := e.suppressed
		e.last, e.suppressed = now, 0
		return true, n
	}
	if len(l.seen) >= MaxKeys {
		for k, e := range l.seen {
			if now.Sub(e.last) >= l.window {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= MaxKeys {
			return true, 0
		}
	}
	l.seen[key] = &entry{last: now}
	return true, 0
}
