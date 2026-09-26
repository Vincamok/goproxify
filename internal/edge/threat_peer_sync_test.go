// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

func TestSyncThreatListsFromPeerAppliesNewerLists(t *testing.T) {
	peerUpdated := time.Date(2026, 9, 26, 12, 0, 0, 0, time.UTC)
	var gotAuth string
	peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/v1/threat-lists/export" {
			http.NotFound(w, r)
			return
		}
		gotAuth = r.Header.Get("Authorization")
		_ = json.NewEncoder(w).Encode(threat.HAPayload{UAData: []byte("sqlmap\nnikto\n"), UAUpdatedAt: peerUpdated})
	}))
	defer peer.Close()

	eng := threat.New(slog.New(slog.NewTextHandler(discardWriter{}, nil)), nil)
	s := &Server{threatEngine: eng}
	s.syncThreatListsFromPeer(context.Background(), peer.Client(), proxy.PeerInfo{Endpoint: peer.URL, Token: "tok-peer"})

	if gotAuth != "Bearer tok-peer" {
		t.Fatalf("Authorization = %q", gotAuth)
	}
	if got := eng.BuildHAPayload().UAUpdatedAt; !got.Equal(peerUpdated) {
		t.Fatalf("la liste UA du pair doit être appliquée (updated_at %v), reçu %v", peerUpdated, got)
	}
}

func TestFetchThreatListsIgnoresUnavailablePeer(t *testing.T) {
	for _, status := range []int{http.StatusNoContent, http.StatusUnauthorized, http.StatusInternalServerError} {
		peer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(status) }))
		if _, ok := fetchThreatLists(context.Background(), peer.Client(), peer.URL, "t"); ok {
			t.Errorf("statut %d : aucune liste attendue", status)
		}
		peer.Close()
	}
	if _, ok := fetchThreatLists(context.Background(), http.DefaultClient, "http://127.0.0.1:1", "t"); ok {
		t.Error("pair injoignable : aucune liste attendue")
	}
}

type discardWriter struct{}

func (discardWriter) Write(p []byte) (int, error) { return len(p), nil }
