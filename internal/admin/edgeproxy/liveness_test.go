// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"
)

func TestLivenessClaim(t *testing.T) {
	l := &liveness{downUntil: map[string]time.Time{}}
	now := time.Now()
	if !l.claim("e", now) {
		t.Fatal("une passerelle jamais en échec est interrogée")
	}
	l.fail("e", now)
	if l.claim("e", now.Add(edgeRetry-time.Second)) {
		t.Error("pas de lecture avant la fin du délai")
	}
	if !l.claim("e", now.Add(edgeRetry)) {
		t.Error("la première lecture après le délai tente sa chance")
	}
	if l.claim("e", now.Add(edgeRetry+time.Second)) {
		t.Error("les lectures qui suivent n'attendent pas l'essai en cours")
	}
	l.ok("e")
	if !l.claim("e", now.Add(edgeRetry+time.Second)) {
		t.Error("une passerelle qui répond est interrogée à nouveau")
	}
}

func TestMarkReachableLiftsDownMark(t *testing.T) {
	edgeLiveness = &liveness{downUntil: map[string]time.Time{}}
	edgeLiveness.fail("e", time.Now())
	if edgeLiveness.claim("e", time.Now()) {
		t.Fatal("la passerelle est écartée après l'échec")
	}
	MarkReachable("e")
	if !edgeLiveness.claim("e", time.Now()) {
		t.Error("une passerelle dont le WebSocket est établi est de nouveau interrogée")
	}
}

func TestDownEdgeIsSkippedForReadsOnly(t *testing.T) {
	edgeLiveness = &liveness{downUntil: map[string]time.Time{}}

	var hits atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.Write([]byte(`{}`))
	}))
	target := Target{Endpoint: srv.URL, Token: "t"}
	srv.Close() // la passerelle ne répond plus : connexion refusée

	c := NewClient()
	if _, err := c.List(context.Background(), target); err == nil || errors.Is(err, ErrEdgeDown) {
		t.Fatalf("la première lecture tente la passerelle et échoue sur le réseau : %v", err)
	}
	if _, err := c.List(context.Background(), target); !errors.Is(err, ErrEdgeDown) {
		t.Fatalf("la lecture suivante est écartée sans appel réseau : %v", err)
	}

	// Une écriture n'est jamais écartée : elle atteint la passerelle dès qu'elle est revenue.
	back := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		w.WriteHeader(http.StatusNoContent)
	}))
	defer back.Close()
	edgeLiveness.fail(back.URL, time.Now())
	target = Target{Endpoint: back.URL, Token: "t"}
	if _, err := c.List(context.Background(), target); !errors.Is(err, ErrEdgeDown) {
		t.Fatalf("lecture écartée pendant le délai : %v", err)
	}
	if err := c.Delete(context.Background(), target, "p1"); err != nil {
		t.Fatalf("la suppression doit partir : %v", err)
	}
	if hits.Load() != 1 {
		t.Errorf("appels reçus = %d, attendu 1 (la suppression)", hits.Load())
	}
	if _, err := c.List(context.Background(), target); errors.Is(err, ErrEdgeDown) {
		t.Error("une réponse de la passerelle la rend de nouveau interrogeable")
	}
}

func TestCancelledReadDoesNotMarkEdgeDown(t *testing.T) {
	edgeLiveness = &liveness{downUntil: map[string]time.Time{}}
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer srv.Close()
	defer close(release)

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	NewClient().List(ctx, Target{Endpoint: srv.URL, Token: "t"})
	if !edgeLiveness.claim(srv.URL, time.Now()) {
		t.Error("l'abandon du client ne met pas la passerelle de côté")
	}
}
