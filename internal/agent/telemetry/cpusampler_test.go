// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"errors"
	"testing"
	"time"
)

func fakeSampler(stats []CPUStat, clock *time.Time) *CPUSampler {
	i := 0
	return &CPUSampler{
		read: func() (CPUStat, error) {
			if i >= len(stats) {
				return CPUStat{}, errors.New("plus de relevé")
			}
			s := stats[i]
			i++
			return s, nil
		},
		wait: func(d time.Duration) { *clock = clock.Add(d) },
		now:  func() time.Time { return *clock },
	}
}

func TestCPUSamplerMeasuresTheWholeInterval(t *testing.T) {
	clock := time.Unix(1000, 0)
	// premier appel : deux relevés à 200 ms (50 % utilisé) ; second appel, 30 s plus tard : 20 % utilisé sur tout l'intervalle
	s := fakeSampler([]CPUStat{
		{Idle: 100, Total: 200},
		{Idle: 150, Total: 300},
		{Idle: 150 + 2400, Total: 300 + 3000},
	}, &clock)

	if got := s.Sample(); got != 50 {
		t.Fatalf("premier relevé = %v, attendu 50", got)
	}
	clock = clock.Add(30 * time.Second)
	if got := s.Sample(); got < 19.99 || got > 20.01 {
		t.Fatalf("relevé sur l'intervalle = %v, attendu 20", got)
	}
}

func TestCPUSamplerReusesLastValueOnQuickRetry(t *testing.T) {
	clock := time.Unix(1000, 0)
	s := fakeSampler([]CPUStat{
		{Idle: 100, Total: 200},
		{Idle: 150, Total: 300},
		{Idle: 160, Total: 310},
	}, &clock)
	first := s.Sample()
	clock = clock.Add(200 * time.Millisecond)
	if got := s.Sample(); got != first {
		t.Fatalf("un réessai immédiat doit renvoyer la dernière valeur (%v), obtenu %v", first, got)
	}
}

func TestCPUSamplerKeepsLastValueOnReadError(t *testing.T) {
	clock := time.Unix(1000, 0)
	s := fakeSampler([]CPUStat{{Idle: 100, Total: 200}, {Idle: 150, Total: 300}}, &clock)
	first := s.Sample()
	clock = clock.Add(30 * time.Second)
	if got := s.Sample(); got != first {
		t.Fatalf("une erreur de lecture doit conserver la dernière valeur (%v), obtenu %v", first, got)
	}
}
