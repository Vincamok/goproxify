// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func shortCfg(ttl string) *router.CacheConfig {
	return &router.CacheConfig{Enabled: true, ValidRules: []router.CacheValidRule{{StatusCodes: []int{200}, TTL: ttl}}}
}

func get(h http.Handler, path string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest("GET", path, nil))
	return rec
}

func TestCache_StaleWhileRevalidate(t *testing.T) {
	var calls atomic.Int32
	cfg := shortCfg("50ms")
	cfg.StaleWhileRevalidate = "10s"
	h := New(t.TempDir()).MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte{byte('a' + calls.Add(1) - 1)}) //nolint:errcheck
	}))

	if got := get(h, "/p").Body.String(); got != "a" {
		t.Fatalf("premier appel = %q", got)
	}
	time.Sleep(80 * time.Millisecond)
	rec := get(h, "/p")
	if rec.Header().Get("X-Cache") != "STALE" || rec.Body.String() != "a" {
		t.Fatalf("attendu STALE 'a', obtenu %s %q", rec.Header().Get("X-Cache"), rec.Body.String())
	}
	deadline := time.Now().Add(2 * time.Second)
	for calls.Load() < 2 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	time.Sleep(20 * time.Millisecond)
	rec = get(h, "/p")
	if rec.Header().Get("X-Cache") != "HIT" || rec.Body.String() != "b" {
		t.Fatalf("attendu HIT 'b' après revalidation, obtenu %s %q", rec.Header().Get("X-Cache"), rec.Body.String())
	}
}

func TestCache_StaleIfError(t *testing.T) {
	var fail atomic.Bool
	cfg := shortCfg("50ms")
	cfg.StaleIfError = "10s"
	h := New(t.TempDir()).MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusBadGateway)
			return
		}
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	get(h, "/p")
	time.Sleep(80 * time.Millisecond)
	fail.Store(true)
	rec := get(h, "/p")
	if rec.Code != 200 || rec.Body.String() != "ok" || rec.Header().Get("X-Cache") != "STALE" {
		t.Fatalf("attendu 200 STALE, obtenu %d %s %q", rec.Code, rec.Header().Get("X-Cache"), rec.Body.String())
	}
}

func TestCache_StaleIfErrorFromBackendDirective(t *testing.T) {
	var fail atomic.Bool
	h := New(t.TempDir()).MiddlewareWithConfig(shortCfg("50ms"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if fail.Load() {
			http.Error(w, "down", http.StatusInternalServerError)
			return
		}
		w.Header().Set("Cache-Control", "stale-if-error=60")
		w.Write([]byte("ok")) //nolint:errcheck
	}))
	get(h, "/p")
	time.Sleep(80 * time.Millisecond)
	fail.Store(true)
	if rec := get(h, "/p"); rec.Code != 200 {
		t.Fatalf("la directive du backend aurait dû servir le stale, code %d", rec.Code)
	}
}

func TestCache_ExpiredWithoutStaleWindowGoesToBackend(t *testing.T) {
	var calls atomic.Int32
	h := New(t.TempDir()).MiddlewareWithConfig(shortCfg("30ms"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		w.Write([]byte("x")) //nolint:errcheck
	}))
	get(h, "/p")
	time.Sleep(60 * time.Millisecond)
	if rec := get(h, "/p"); rec.Header().Get("X-Cache") != "MISS" || calls.Load() != 2 {
		t.Fatalf("attendu MISS, obtenu %s (calls=%d)", rec.Header().Get("X-Cache"), calls.Load())
	}
}

func TestCache_CoalescesConcurrentMisses(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	h := New(t.TempDir()).MiddlewareWithConfig(shortCfg("1m"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
		w.Write([]byte("slow")) //nolint:errcheck
	}))

	var wg sync.WaitGroup
	results := make([]*httptest.ResponseRecorder, 5)
	for i := range results {
		wg.Add(1)
		go func() {
			defer wg.Done()
			results[i] = get(h, "/slow")
		}()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()

	if calls.Load() != 1 {
		t.Fatalf("le backend a reçu %d requêtes, attendu 1", calls.Load())
	}
	coalesced := 0
	for _, r := range results {
		if r.Body.String() != "slow" {
			t.Fatalf("corps = %q", r.Body.String())
		}
		if r.Header().Get("X-Cache") == "COALESCED" {
			coalesced++
		}
	}
	if coalesced != 4 {
		t.Fatalf("%d réponses COALESCED, attendu 4", coalesced)
	}
}

func TestCache_DisableCoalescing(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	cfg := shortCfg("1m")
	cfg.DisableCoalescing = true
	h := New(t.TempDir()).MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		<-release
	}))
	var wg sync.WaitGroup
	for range 3 {
		wg.Add(1)
		go func() { defer wg.Done(); get(h, "/slow") }()
	}
	time.Sleep(150 * time.Millisecond)
	close(release)
	wg.Wait()
	if calls.Load() != 3 {
		t.Fatalf("calls = %d, attendu 3", calls.Load())
	}
}

func TestCache_UncacheableResponseNotSharedBetweenClients(t *testing.T) {
	var calls atomic.Int32
	release := make(chan struct{})
	h := New(t.TempDir()).MiddlewareWithConfig(shortCfg("1m"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		n := calls.Add(1)
		if n == 1 {
			<-release
		}
		w.Header().Set("Cache-Control", "private")
		w.Write([]byte{byte('0' + n)}) //nolint:errcheck
	}))
	var wg sync.WaitGroup
	bodies := make([]string, 2)
	for i := range bodies {
		wg.Add(1)
		go func() { defer wg.Done(); bodies[i] = get(h, "/me").Body.String() }()
		time.Sleep(80 * time.Millisecond)
	}
	close(release)
	wg.Wait()
	if calls.Load() != 2 || bodies[0] == bodies[1] {
		t.Fatalf("réponse privée partagée : calls=%d bodies=%v", calls.Load(), bodies)
	}
}

func TestCache_PurgeByTagAndPath(t *testing.T) {
	dc := New(t.TempDir())
	h := dc.MiddlewareWithConfig(shortCfg("1m"))(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/a":
			w.Header().Set("Cache-Tag", "news, home")
		case "/b":
			w.Header().Set("Surrogate-Key", "news")
		}
		w.Write([]byte(r.URL.Path)) //nolint:errcheck
	}))
	for _, p := range []string{"/a", "/b", "/c", "/d?x=1"} {
		get(h, p)
	}
	if rec := get(h, "/a"); rec.Header().Get("Cache-Tag") != "" {
		t.Fatal("Cache-Tag ne doit pas atteindre le client")
	}

	if n, _ := dc.PurgeMatching(PurgeSelector{Tags: []string{"news"}}); n != 2 {
		t.Fatalf("purge par tag = %d, attendu 2", n)
	}
	if get(h, "/c").Header().Get("X-Cache") != "HIT" {
		t.Fatal("/c ne devait pas être purgée")
	}
	if n, _ := dc.PurgeMatching(PurgeSelector{Paths: []string{"/c"}}); n != 1 {
		t.Fatalf("purge par chemin = %d, attendu 1", n)
	}
	if n, _ := dc.PurgeMatching(PurgeSelector{Paths: []string{"/d*"}}); n != 1 {
		t.Fatalf("purge par préfixe = %d, attendu 1", n)
	}
	get(h, "/e")
	if n, _ := dc.Purge(); n != 1 {
		t.Fatalf("purge totale = %d, attendu 1", n)
	}
}
