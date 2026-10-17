// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
)

func TestPeerHealthBackoff(t *testing.T) {
	var h peerHealth
	now := time.Now()
	if !h.due("p", now) {
		t.Fatal("un pair inconnu doit être contacté")
	}

	want := []time.Duration{15 * time.Second, 30 * time.Second, 60 * time.Second, 2 * time.Minute, 2 * time.Minute}
	for i, d := range want {
		h.record("p", false, now)
		if h.due("p", now.Add(d-time.Second)) {
			t.Errorf("échec %d : pas de nouvel essai avant %v", i+1, d)
		}
		if !h.due("p", now.Add(d)) {
			t.Errorf("échec %d : nouvel essai attendu après %v", i+1, d)
		}
	}

	h.record("p", true, now)
	if !h.due("p", now) {
		t.Error("un pair qui répond est de nouveau synchronisé à chaque tour")
	}
	h.record("p", false, now)
	if h.due("p", now.Add(14*time.Second)) || !h.due("p", now.Add(15*time.Second)) {
		t.Error("après un succès, le délai repart de 15 s")
	}
}

func TestPeerHealthRetainForgetsRemovedPeers(t *testing.T) {
	var h peerHealth
	now := time.Now()
	h.record("a", false, now)
	h.record("b", false, now)
	h.retain([]proxy.PeerInfo{{Name: "a"}})
	if h.due("a", now) {
		t.Error("le pair conservé garde son attente")
	}
	if !h.due("b", now) {
		t.Error("le pair retiré de la liste est oublié")
	}
}

func TestProbePeer(t *testing.T) {
	var auth string
	ok := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		auth = r.Header.Get("Authorization")
		if r.URL.Path != "/internal/v1/health" {
			http.NotFound(w, r)
		}
	}))
	defer ok.Close()
	if !probePeer(context.Background(), proxy.PeerInfo{Endpoint: ok.URL, Token: "tok"}) {
		t.Error("un pair qui répond 200 est joignable")
	}
	if auth != "Bearer tok" {
		t.Errorf("Authorization = %q", auth)
	}

	broken := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer broken.Close()
	if probePeer(context.Background(), proxy.PeerInfo{Endpoint: broken.URL}) {
		t.Error("un pair qui répond 500 n'est pas joignable")
	}

	release := make(chan struct{})
	silent := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		select {
		case <-release:
		case <-r.Context().Done():
		}
	}))
	defer silent.Close()
	defer close(release)
	start := time.Now()
	if probePeer(context.Background(), proxy.PeerInfo{Endpoint: silent.URL}) {
		t.Error("un pair muet n'est pas joignable")
	}
	if d := time.Since(start); d > peerProbeTimeout+time.Second {
		t.Errorf("le sondage a duré %v, borné à %v", d, peerProbeTimeout)
	}
}
