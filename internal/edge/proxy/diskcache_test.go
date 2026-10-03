// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestParseTTL(t *testing.T) {
	cases := []struct {
		in   string
		want time.Duration
	}{
		{"10m", 10 * time.Minute},
		{"1h", time.Hour},
		{"30s", 30 * time.Second},
		{"60", 60 * time.Second},
		{"invalid", 0},
		{"", 0},
	}
	for _, tc := range cases {
		got := parseTTL(tc.in)
		if got != tc.want {
			t.Errorf("parseTTL(%q) = %v, want %v", tc.in, got, tc.want)
		}
	}
}

func TestResolveTTL_ValidRules(t *testing.T) {
	cfg := &router.CacheConfig{
		ValidRules: []router.CacheValidRule{
			{StatusCodes: []int{200}, TTL: "5m"},
			{StatusCodes: []int{404}, TTL: "10s"},
		},
	}
	if got := resolveTTL(200, http.Header{}, cfg); got != 5*time.Minute {
		t.Errorf("got %v, want 5m", got)
	}
	if got := resolveTTL(404, http.Header{}, cfg); got != 10*time.Second {
		t.Errorf("got %v, want 10s", got)
	}
	if got := resolveTTL(500, http.Header{}, cfg); got != 0 {
		t.Errorf("got %v, want 0 (no matching rule)", got)
	}
}

func TestResolveTTL_Fallback(t *testing.T) {
	h := http.Header{"Cache-Control": []string{"max-age=120"}}
	if got := resolveTTL(200, h, nil); got != 120*time.Second {
		t.Errorf("got %v, want 120s", got)
	}
	h2 := http.Header{"Cache-Control": []string{"no-store"}}
	if got := resolveTTL(200, h2, nil); got != 0 {
		t.Errorf("got %v, want 0", got)
	}
}

func TestIsBypass_Header(t *testing.T) {
	cfg := &router.CacheConfig{BypassHeaders: []string{"X-No-Cache"}}
	req := httptest.NewRequest("GET", "/", nil)
	if isBypass(req, cfg) {
		t.Fatal("should not bypass without the header")
	}
	req.Header.Set("X-No-Cache", "1")
	if !isBypass(req, cfg) {
		t.Fatal("should bypass when header is set")
	}
}

func TestIsBypass_Cookie(t *testing.T) {
	cfg := &router.CacheConfig{BypassCookies: []string{"session"}}
	req := httptest.NewRequest("GET", "/", nil)
	if isBypass(req, cfg) {
		t.Fatal("should not bypass without cookie")
	}
	req.AddCookie(&http.Cookie{Name: "session", Value: "abc"})
	if !isBypass(req, cfg) {
		t.Fatal("should bypass when cookie is present")
	}
}

func TestMiddlewareWithConfig_CacheHitMiss(t *testing.T) {
	dir := t.TempDir()
	dc := New(dir)
	cfg := &router.CacheConfig{
		Enabled:    true,
		ValidRules: []router.CacheValidRule{{StatusCodes: []int{200}, TTL: "1m"}},
	}

	calls := 0
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
		w.Write([]byte("hello"))
	})
	h := dc.MiddlewareWithConfig(cfg)(handler)

	req := httptest.NewRequest("GET", "/test", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Header().Get("X-Cache") != "MISS" {
		t.Errorf("first request should be MISS, got %q", rec.Header().Get("X-Cache"))
	}

	rec2 := httptest.NewRecorder()
	h.ServeHTTP(rec2, req)
	if rec2.Header().Get("X-Cache") != "HIT" {
		t.Errorf("second request should be HIT, got %q", rec2.Header().Get("X-Cache"))
	}
	if calls != 1 {
		t.Errorf("backend should only be called once, got %d", calls)
	}
}

func TestMiddlewareWithConfig_BypassSkipsCache(t *testing.T) {
	dir := t.TempDir()
	dc := New(dir)
	cfg := &router.CacheConfig{
		Enabled:       true,
		ValidRules:    []router.CacheValidRule{{TTL: "1m"}},
		BypassHeaders: []string{"X-Bypass"},
	}

	calls := 0
	h := dc.MiddlewareWithConfig(cfg)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		w.WriteHeader(http.StatusOK)
	}))

	req := httptest.NewRequest("GET", "/bypass", nil)
	req.Header.Set("X-Bypass", "true")
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if calls != 2 {
		t.Errorf("bypass should call backend every time, got %d", calls)
	}
}

func cacheTestHandler(calls *int, hdr map[string]string) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*calls++
		for k, v := range hdr {
			w.Header().Set(k, v)
		}
		w.Write([]byte("who=" + r.Header.Get("X-User") + r.Header.Get("Cookie"))) //nolint:errcheck
	})
}

func cacheTestCfg() *router.CacheConfig {
	return &router.CacheConfig{Enabled: true, ValidRules: []router.CacheValidRule{{StatusCodes: []int{200}, TTL: "1m"}}}
}

func TestCache_RequestWithCookieOrAuthNeverCachedNorServed(t *testing.T) {
	for _, tc := range []struct{ name, k, v string }{
		{"cookie", "Cookie", "sid=alice"},
		{"authorization", "Authorization", "Bearer alice"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			calls := 0
			h := New(t.TempDir()).MiddlewareWithConfig(cacheTestCfg())(cacheTestHandler(&calls, nil))
			req := httptest.NewRequest("GET", "/me", nil)
			req.Header.Set(tc.k, tc.v)
			h.ServeHTTP(httptest.NewRecorder(), req)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, httptest.NewRequest("GET", "/me", nil))
			if rec.Header().Get("X-Cache") == "HIT" || calls != 2 {
				t.Fatalf("réponse authentifiée resservie à l'anonyme (calls=%d)", calls)
			}
		})
	}
}

func TestCache_PrivateNoStoreSetCookieNotStored(t *testing.T) {
	for _, hdr := range []map[string]string{
		{"Cache-Control": "private, max-age=60"},
		{"Cache-Control": "no-store"},
		{"Set-Cookie": "sid=x"},
		{"Vary": "*"},
	} {
		calls := 0
		h := New(t.TempDir()).MiddlewareWithConfig(cacheTestCfg())(cacheTestHandler(&calls, hdr))
		req := httptest.NewRequest("GET", "/x", nil)
		h.ServeHTTP(httptest.NewRecorder(), req)
		h.ServeHTTP(httptest.NewRecorder(), req)
		if calls != 2 {
			t.Errorf("%v : réponse mise en cache (calls=%d)", hdr, calls)
		}
	}
}

func TestCache_PublicStillCachedWithoutCookie(t *testing.T) {
	calls := 0
	h := New(t.TempDir()).MiddlewareWithConfig(cacheTestCfg())(cacheTestHandler(&calls, map[string]string{"Cache-Control": "public, max-age=60"}))
	req := httptest.NewRequest("GET", "/s.css", nil)
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if calls != 1 {
		t.Fatalf("ressource publique non mise en cache (calls=%d)", calls)
	}
}

func TestCache_VaryHonored(t *testing.T) {
	calls := 0
	h := New(t.TempDir()).MiddlewareWithConfig(cacheTestCfg())(cacheTestHandler(&calls, map[string]string{"Vary": "X-User"}))
	get := func(u string) string {
		req := httptest.NewRequest("GET", "/v", nil)
		req.Header.Set("X-User", u)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if get("a") != "who=a" || get("b") != "who=b" || get("a") != "who=a" {
		t.Fatal("variante servie au mauvais client")
	}
	if calls != 2 {
		t.Fatalf("attendu 2 appels backend (a, b ; a en HIT), got %d", calls)
	}
}

func TestCache_VaryCookiesAndIgnoreCookies(t *testing.T) {
	cfg := cacheTestCfg()
	cfg.VaryCookies = []string{"lang"}
	calls := 0
	h := New(t.TempDir()).MiddlewareWithConfig(cfg)(cacheTestHandler(&calls, nil))
	get := func(c string) string {
		req := httptest.NewRequest("GET", "/l", nil)
		req.Header.Set("Cookie", c)
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec.Body.String()
	}
	if get("lang=fr") == get("lang=en") {
		t.Fatal("vary_cookies : valeurs distinctes mélangées")
	}
	get("lang=fr")
	if calls != 2 {
		t.Fatalf("lang=fr devait être en HIT, calls=%d", calls)
	}

	cfg2 := cacheTestCfg()
	cfg2.IgnoreCookies = true
	calls = 0
	h = New(t.TempDir()).MiddlewareWithConfig(cfg2)(cacheTestHandler(&calls, nil))
	req := httptest.NewRequest("GET", "/i", nil)
	req.Header.Set("Cookie", "a=1")
	h.ServeHTTP(httptest.NewRecorder(), req)
	h.ServeHTTP(httptest.NewRecorder(), req)
	if calls != 1 {
		t.Fatalf("ignore_cookies : attendu 1 appel, got %d", calls)
	}
}
