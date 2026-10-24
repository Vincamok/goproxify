// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package behavior

import (
	"sync"
	"time"
)

const (
	// trustRetention : une IP sans nouvelle requête depuis aussi longtemps est oubliée (vie privée : l'historique propre n'est
	// pas conservé indéfiniment, et l'effacement RGPD d'une IP le retire aussitôt).
	trustRetention  = 7 * 24 * time.Hour
	maxTrustEntries = 200000

	maxCleanBonus   = 5 // un point par centaine de requêtes propres (le bonus historique du WAF)
	maxHistoryBonus = 3 // un point par jour d'historique sans signal, à partir de minHistoryClean requêtes propres
	minHistoryClean = 50
)

// trustEntry : ce que l'on sait d'une IP qui se comporte bien.
type trustEntry struct {
	First int64 // début de l'historique propre (UnixNano) ; repart de zéro après un signal
	Last  int64
	Clean int64 // requêtes propres depuis First
}

// trustBook retient plus longtemps que la fenêtre le bon comportement des IP : le bonus de confiance repousse d'autant le seuil
// de ban d'une IP à longue histoire propre.
type trustBook struct {
	mu sync.Mutex
	m  map[string]*trustEntry
}

func newTrustBook() *trustBook { return &trustBook{m: map[string]*trustEntry{}} }

// observe compte une requête de l'IP. Un signal fait perdre la moitié des requêtes propres et repart l'historique : la
// confiance se regagne.
func (b *trustBook) observe(ip string, at time.Time, clean, suspicious bool) {
	if !clean && !suspicious {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[ip]
	if e == nil {
		if !clean {
			return
		}
		if len(b.m) >= maxTrustEntries {
			for k := range b.m {
				delete(b.m, k)
				break
			}
		}
		e = &trustEntry{First: at.UnixNano()}
		b.m[ip] = e
	}
	e.Last = at.UnixNano()
	if suspicious {
		e.Clean /= 2
		e.First = e.Last
		return
	}
	e.Clean++
}

// raiseClean aligne l'historique propre sur celui d'un pair HA.
func (b *trustBook) raiseClean(ip string, clean int64, now time.Time) {
	if clean <= 0 {
		return
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	e := b.m[ip]
	if e == nil {
		if len(b.m) >= maxTrustEntries {
			return
		}
		e = &trustEntry{First: now.UnixNano(), Last: now.UnixNano()}
		b.m[ip] = e
	}
	if clean > e.Clean {
		e.Clean = clean
	}
}

// bonus : points ajoutés au seuil de ban. clean peut déjà contenir un compteur plus récent que celui du livre.
func (b *trustBook) bonus(ip string, clean int64, now time.Time) int {
	days := 0
	b.mu.Lock()
	if e := b.m[ip]; e != nil {
		if e.Clean > clean {
			clean = e.Clean
		}
		if e.Clean >= minHistoryClean {
			days = int(now.Sub(time.Unix(0, e.First)) / (24 * time.Hour))
		}
	}
	b.mu.Unlock()
	bonus := int(clean / 100)
	if bonus > maxCleanBonus {
		bonus = maxCleanBonus
	}
	if days > maxHistoryBonus {
		days = maxHistoryBonus
	}
	if days < 0 {
		days = 0
	}
	return bonus + days
}

func (b *trustBook) forget(ip string) {
	b.mu.Lock()
	delete(b.m, ip)
	b.mu.Unlock()
}

func (b *trustBook) gc(now time.Time) {
	cutoff := now.Add(-trustRetention).UnixNano()
	b.mu.Lock()
	for ip, e := range b.m {
		if e.Last < cutoff {
			delete(b.m, ip)
		}
	}
	b.mu.Unlock()
}

// TrustState est la forme persistée d'un historique propre.
type TrustState struct {
	First int64 `json:"first"`
	Last  int64 `json:"last"`
	Clean int64 `json:"clean"`
}

func (b *trustBook) export(now time.Time) map[string]TrustState {
	cutoff := now.Add(-trustRetention).UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()
	out := make(map[string]TrustState, len(b.m))
	for ip, e := range b.m {
		if e.Last >= cutoff {
			out[ip] = TrustState{First: e.First, Last: e.Last, Clean: e.Clean}
		}
	}
	return out
}

func (b *trustBook) restore(in map[string]TrustState, now time.Time) {
	cutoff := now.Add(-trustRetention).UnixNano()
	b.mu.Lock()
	defer b.mu.Unlock()
	for ip, t := range in {
		if t.Last < cutoff || t.Clean <= 0 || t.First > t.Last || len(b.m) >= maxTrustEntries {
			continue
		}
		if _, ok := b.m[ip]; !ok {
			b.m[ip] = &trustEntry{First: t.First, Last: t.Last, Clean: t.Clean}
		}
	}
}

// TrustBonus retourne le bonus de confiance d'une IP : un point par centaine de requêtes propres (au plus 5), plus un point
// par jour d'historique sans signal (au plus 3). Il s'ajoute au seuil de ban effectif.
func (s *Store) TrustBonus(ip string) int {
	s.mu.RLock()
	p := s.profiles[ip]
	s.mu.RUnlock()
	var clean int64
	if p != nil {
		p.mu.Lock()
		clean = p.cleanRequests
		p.mu.Unlock()
	}
	return s.trust.bonus(ip, clean, s.now())
}
