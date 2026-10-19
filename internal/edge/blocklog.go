// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"sync"
	"time"
)

const (
	blockLogWindow = time.Minute
	// blockLogMaxKeys borne la mémoire sous une attaque venue de très nombreuses adresses : au-delà,
	// les refus sont journalisés sans regroupement plutôt que de grossir la table.
	blockLogMaxKeys = 20000
)

// repeatLimiter laisse passer une ligne de journal par clé et par fenêtre, et compte les refus
// écartés entre deux lignes. Un scanner qui insiste sur une IP déjà bannie produisait une ligne par
// requête (jusqu'à 12 000 pour une seule IP), soit plus de la moitié des logs de l'Admin.
type repeatLimiter struct {
	mu     sync.Mutex
	window time.Duration
	seen   map[string]*repeatEntry
	now    func() time.Time
}

type repeatEntry struct {
	last       time.Time
	suppressed int
}

func newRepeatLimiter(window time.Duration) *repeatLimiter {
	return &repeatLimiter{window: window, seen: make(map[string]*repeatEntry), now: time.Now}
}

// Allow indique s'il faut journaliser ce refus et, si oui, combien de refus identiques ont été
// écartés depuis la ligne précédente.
func (l *repeatLimiter) Allow(key string) (log bool, suppressed int) {
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
	if len(l.seen) >= blockLogMaxKeys {
		for k, e := range l.seen {
			if now.Sub(e.last) >= l.window {
				delete(l.seen, k)
			}
		}
		if len(l.seen) >= blockLogMaxKeys {
			return true, 0
		}
	}
	l.seen[key] = &repeatEntry{last: now}
	return true, 0
}

// blockedAttrs ajoute le nombre de refus regroupés à une ligne de journal, quand il y en a.
func blockedAttrs(suppressed int, attrs ...any) []any {
	if suppressed > 0 {
		attrs = append(attrs, "repeats", suppressed)
	}
	return attrs
}
