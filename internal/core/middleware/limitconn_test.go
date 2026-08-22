// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/core/router"
)

func TestLimitConn_AllowsUnderLimit(t *testing.T) {
	cfg := &router.LimitConnConfig{MaxPerIP: 3}
	h := LimitConn(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	req := httptest.NewRequest("GET", "/", nil)
	req.RemoteAddr = "1.2.3.4:1234"
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}

func TestLimitConn_BlocksOverLimit(t *testing.T) {
	cfg := &router.LimitConnConfig{MaxPerIP: 1}

	ready := make(chan struct{})
	done := make(chan struct{})
	block := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		close(ready)
		<-done
		w.WriteHeader(http.StatusOK)
	})
	h := LimitConn(cfg)(block)

	// reset store for this test IP
	ip := "9.8.7.6"
	lcStore.mu.Lock()
	delete(lcStore.counts, ip)
	lcStore.mu.Unlock()

	var wg sync.WaitGroup
	wg.Add(1)
	go func() {
		defer wg.Done()
		req := httptest.NewRequest("GET", "/", nil)
		req.RemoteAddr = ip + ":1234"
		h.ServeHTTP(httptest.NewRecorder(), req)
	}()

	<-ready // first request is in-flight

	// second request should be rejected
	rec2 := httptest.NewRecorder()
	req2 := httptest.NewRequest("GET", "/", nil)
	req2.RemoteAddr = ip + ":5678"
	h.ServeHTTP(rec2, req2)
	if rec2.Code != http.StatusServiceUnavailable {
		t.Fatalf("expected 503, got %d", rec2.Code)
	}

	close(done)
	wg.Wait()
}

func TestLimitConn_Disabled(t *testing.T) {
	h := LimitConn(nil)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", "/", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
}
