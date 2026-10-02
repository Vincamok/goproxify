// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestCircuitBreaker_PerBackendOpen(t *testing.T) {
	cb := newCB(&router.CBConfig{Threshold: 2, Timeout: time.Hour})
	cb.RecordFailure("a")
	if !cb.Allow("a") {
		t.Fatal("sous le seuil, a doit rester tentable")
	}
	cb.RecordFailure("a")
	if cb.Allow("a") {
		t.Fatal("seuil atteint : a doit être court-circuité")
	}
	if !cb.Allow("b") {
		t.Fatal("b ne doit pas être affecté par les échecs de a")
	}
	if cb.RetryAfter([]string{"a"}) <= 0 {
		t.Fatal("RetryAfter doit être positif pour un circuit ouvert")
	}
}

func TestCircuitBreaker_HalfOpenSingleProbe(t *testing.T) {
	cb := newCB(&router.CBConfig{Threshold: 1, Timeout: 20 * time.Millisecond})
	cb.RecordFailure("a")
	time.Sleep(30 * time.Millisecond)
	if !cb.Allow("a") {
		t.Fatal("half-open : la première sonde doit passer")
	}
	if cb.Allow("a") {
		t.Fatal("half-open : une seule sonde à la fois")
	}
	cb.RecordFailure("a")
	if cb.Allow("a") {
		t.Fatal("échec de la sonde : circuit rouvert")
	}
	time.Sleep(30 * time.Millisecond)
	if !cb.Allow("a") {
		t.Fatal("nouvelle sonde après timeout")
	}
	cb.RecordSuccess("a")
	if !cb.Allow("a") || !cb.Allow("a") {
		t.Fatal("succès de la sonde : circuit refermé")
	}
}
