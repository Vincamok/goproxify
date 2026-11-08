// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"sync"
	"time"
)

// CPUSampler mesure l'usage CPU de l'hôte sur l'intervalle qui sépare deux appels. Un relevé de quelques centaines de
// millisecondes pris toutes les 30 s ne dit presque rien de la charge réelle : il tombe au hasard sur un pic ou un creux.
type CPUSampler struct {
	mu   sync.Mutex
	read func() (CPUStat, error)
	wait func(time.Duration)
	now  func() time.Time
	prev CPUStat
	at   time.Time
	last float64
	ok   bool
}

func NewCPUSampler() *CPUSampler {
	return &CPUSampler{read: ReadCPUStat, wait: time.Sleep, now: time.Now}
}

// Sample renvoie l'usage CPU (%) depuis l'appel précédent. Le premier appel n'a pas d'historique : il mesure sur 200 ms.
// Deux appels à moins d'une seconde d'écart (réessai d'un envoi) renvoient la dernière valeur au lieu d'une mesure sans sens.
func (s *CPUSampler) Sample() float64 {
	s.mu.Lock()
	defer s.mu.Unlock()
	cur, err := s.read()
	if err != nil {
		return s.last
	}
	if !s.ok {
		s.wait(200 * time.Millisecond)
		next, err := s.read()
		if err != nil {
			return 0
		}
		s.last = CPUUsagePct(cur, next)
		s.prev, s.at, s.ok = next, s.now(), true
		return s.last
	}
	if s.now().Sub(s.at) < time.Second {
		return s.last
	}
	s.last = CPUUsagePct(s.prev, cur)
	s.prev, s.at = cur, s.now()
	return s.last
}
