// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"errors"
	"sync"
	"time"
)

// edgeRetry est le délai pendant lequel une passerelle qui n'a pas répondu n'est plus interrogée en lecture.
const edgeRetry = 30 * time.Second

// ErrEdgeDown est renvoyée à la place d'une lecture vers une passerelle qui vient de ne pas répondre.
var ErrEdgeDown = errors.New("passerelle injoignable, nouvel essai différé")

// liveness retient les passerelles injoignables. Les lectures (liste des proxies, tableau de bord, MCP…)
// parcourent toutes les passerelles l'une après l'autre : une passerelle en attente, qui ne répond pas, leur
// coûtait à chacune le timeout entier (15 s). Seule la première lecture après le délai paie un essai ; les
// autres échouent aussitôt. Les écritures ne sont jamais écartées : elles réessaient toujours.
type liveness struct {
	mu        sync.Mutex
	downUntil map[string]time.Time
}

var edgeLiveness = &liveness{downUntil: map[string]time.Time{}}

// claim dit si une lecture peut partir. Après un échec, la première lecture à passer le délai prend l'essai à son
// compte (le délai repart) : celles qui la suivent n'attendent pas son résultat.
func (l *liveness) claim(endpoint string, now time.Time) bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	until, down := l.downUntil[endpoint]
	if !down {
		return true
	}
	if now.Before(until) {
		return false
	}
	l.downUntil[endpoint] = now.Add(edgeRetry)
	return true
}

func (l *liveness) fail(endpoint string, now time.Time) {
	l.mu.Lock()
	l.downUntil[endpoint] = now.Add(edgeRetry)
	l.mu.Unlock()
}

func (l *liveness) ok(endpoint string) {
	l.mu.Lock()
	delete(l.downUntil, endpoint)
	l.mu.Unlock()
}
