// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestRateLimitBlocksAndRetryAfter(t *testing.T) {
	// Store isolé pour le test
	old := rlStore
	rlStore = &rateLimitStore{
		buckets:    make(map[string]*rateLimiter),
		idleTTL:    old.idleTTL,
		purgeEvery: old.purgeEvery,
	}
	t.Cleanup(func() { rlStore = old })

	cfg := &router.RateLimitConfig{RequestsPerSecond: 1, Burst: 1}
	h := RateLimit(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "10.0.0.10:12345"
	req.Header.Set("X-Forwarded-For", "198.51.100.7")

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusOK {
		t.Fatalf("first: %d", rr.Code)
	}

	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusTooManyRequests {
		t.Fatalf("second: %d", rr.Code)
	}
	if rr.Header().Get("Retry-After") != "1" {
		t.Fatalf("Retry-After: %q", rr.Header().Get("Retry-After"))
	}

	// Autre IP XFF = bucket distinct
	req2 := httptest.NewRequest(http.MethodGet, "/", nil)
	req2.RemoteAddr = "10.0.0.10:12345"
	req2.Header.Set("X-Forwarded-For", "198.51.100.8")
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, req2)
	if rr.Code != http.StatusOK {
		t.Fatalf("other client: %d", rr.Code)
	}
}

func TestBotUABlacklistAndMonitor(t *testing.T) {
	nextOK := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})

	block := BotProtection(&router.BotConfig{Enabled: true, Mode: "block"})(nextOK)
	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.Header.Set("User-Agent", "sqlmap/1.0")
	block.ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("block ua: %d", rr.Code)
	}

	monitor := BotProtection(&router.BotConfig{Enabled: true, Mode: "monitor"})(nextOK)
	rr = httptest.NewRecorder()
	monitor.ServeHTTP(rr, req)
	if rr.Code != http.StatusNoContent {
		t.Fatalf("monitor should pass: %d", rr.Code)
	}
}

func TestBotChallengeEscapesRedirect(t *testing.T) {
	h := BotProtection(&router.BotConfig{
		Enabled:         true,
		JSChallenge:     true,
		ChallengeSecret: "s",
	})(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))

	rr := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodGet, `/x?q="</script><script>alert(1)</script>`, nil)
	req.Header.Set("User-Agent", "Mozilla/5.0")
	h.ServeHTTP(rr, req)
	body := rr.Body.String()
	if strings.Contains(body, `"</script><script>`) {
		t.Fatal("unescaped script breakout in challenge page")
	}
}
