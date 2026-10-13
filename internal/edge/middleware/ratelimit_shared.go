// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"sync"
	"time"
)

// Débit instantané partagé entre les passerelles d'un groupe HA (rate_limit.shared).
//
// Chaque passerelle mesure le débit qu'elle admet par clé (fenêtre glissante d'une seconde, dix cases de 100 ms) et
// le publie ; elle reçoit celui de ses pairs et retire leur part du débit autorisé : avec rps = 100 et un pair qui
// admet 60 requêtes par seconde pour cette clé, le seau local se recharge à 40. Pas de coordinateur : sans pair
// joignable (ou des annonces périmées) le débit local est entier, comme avant — l'Admin n'intervient jamais
// (ADR 0006). Le plancher évite qu'une passerelle soit affamée par un pair qui annonce plus que le débit entier ;
// la rafale (burst) reste celle de chaque passerelle.
const (
	rateSlots     = 10
	rateSlotSpan  = 100 * time.Millisecond
	rateFreshness = 1500 * time.Millisecond // une annonce plus ancienne est ignorée (3 synchronisations manquées)
	rateFloor     = 0.1                     // part minimale du débit autorisé qu'une passerelle garde
	rateMaxKeys   = 50000
)

// RateEntry est le débit local admis pour une clé partagée, échangé entre passerelles d'un groupe HA.
type RateEntry struct {
	Key  string  `json:"key"`
	Rate float64 `json:"rate"` // requêtes admises par seconde
}

type rateTracker struct {
	slots [rateSlots]int
	idx   int64 // numéro de la case courante (temps / 100 ms)
	seen  time.Time
}

func (t *rateTracker) advance(now time.Time) {
	cur := now.UnixNano() / int64(rateSlotSpan)
	if t.idx == 0 {
		t.idx = cur
		return
	}
	gap := cur - t.idx
	if gap <= 0 {
		return
	}
	if gap >= rateSlots {
		t.slots = [rateSlots]int{}
	} else {
		for i := int64(1); i <= gap; i++ {
			t.slots[(t.idx+i)%rateSlots] = 0
		}
	}
	t.idx = cur
}

func (t *rateTracker) add(now time.Time) {
	t.advance(now)
	t.slots[t.idx%rateSlots]++
	t.seen = now
}

func (t *rateTracker) rate(now time.Time) float64 {
	t.advance(now)
	n := 0
	for _, c := range t.slots {
		n += c
	}
	return float64(n) // dix cases de 100 ms = une seconde
}

type peerRate struct {
	rate float64
	at   time.Time
}

type rateShareStore struct {
	mu       sync.Mutex
	local    map[string]*rateTracker
	peers    map[string]map[string]peerRate // clé → pair → débit annoncé
	lastSeen time.Time                      // dernière admission d'une requête partagée
}

var rateShares = &rateShareStore{local: map[string]*rateTracker{}, peers: map[string]map[string]peerRate{}}

// peerRateSum additionne les débits récents annoncés par les pairs pour key.
func (s *rateShareStore) peerRateSum(key string, now time.Time) float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	var sum float64
	for peer, pr := range s.peers[key] {
		if now.Sub(pr.at) > rateFreshness {
			delete(s.peers[key], peer)
			continue
		}
		sum += pr.rate
	}
	return sum
}

func (s *rateShareStore) admitted(key string, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if len(s.local) >= rateMaxKeys {
		for k, t := range s.local {
			if now.Sub(t.seen) > 5*time.Second {
				delete(s.local, k)
			}
		}
	}
	t := s.local[key]
	if t == nil {
		if len(s.local) >= rateMaxKeys {
			return // borne mémoire : ce client n'est plus compté, le débit local reste appliqué
		}
		t = &rateTracker{}
		s.local[key] = t
	}
	t.add(now)
	s.lastSeen = now
}

// effectiveRate est le débit de recharge du seau local compte tenu de celui des pairs.
func effectiveRate(rps, peers float64) float64 {
	return max(rps-peers, rps*rateFloor)
}

// ExportRates retourne le débit admis localement pour les clés partagées encore actives.
func ExportRates() []RateEntry { return rateShares.export(time.Now()) }

func (s *rateShareStore) export(now time.Time) []RateEntry {
	s.mu.Lock()
	defer s.mu.Unlock()
	var out []RateEntry
	for k, t := range s.local {
		if r := t.rate(now); r > 0 {
			out = append(out, RateEntry{Key: k, Rate: r})
		}
	}
	return out
}

// MergeRates enregistre les débits annoncés par le pair peer (la dernière annonce remplace la précédente).
func MergeRates(peer string, entries []RateEntry) { rateShares.merge(peer, entries, time.Now()) }

func (s *rateShareStore) merge(peer string, entries []RateEntry, now time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	seen := map[string]bool{}
	for _, e := range entries {
		if e.Rate <= 0 || e.Key == "" {
			continue
		}
		seen[e.Key] = true
		m := s.peers[e.Key]
		if m == nil {
			if len(s.peers) >= rateMaxKeys {
				continue
			}
			m = map[string]peerRate{}
			s.peers[e.Key] = m
		}
		m[peer] = peerRate{rate: e.Rate, at: now}
	}
	// Une clé que le pair n'annonce plus est au repos chez lui.
	for k, m := range s.peers {
		if _, ok := m[peer]; ok && !seen[k] {
			delete(m, peer)
		}
		if len(m) == 0 {
			delete(s.peers, k)
		}
	}
}

// HasSharedRates dit si un débit partagé a été admis récemment (inutile d'interroger les pairs sinon).
func HasSharedRates() bool { return rateShares.active(time.Now()) }

func (s *rateShareStore) active(now time.Time) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	return !s.lastSeen.IsZero() && now.Sub(s.lastSeen) < 30*time.Second
}
