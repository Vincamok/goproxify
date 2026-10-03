// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func newTestHandler(route *router.Route) *Handler {
	return NewHandler(route, NewBackendHealth(slog.Default()), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())
}

func TestStickyCookieReachesClient(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	h := newTestHandler(&router.Route{
		Host:         "app.test",
		StickyCookie: "LABSID",
		Backends:     []router.Backend{{URL: backend.URL}},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var got *http.Cookie
	for _, c := range resp.Cookies() {
		if c.Name == "LABSID" {
			got = c
		}
	}
	if got == nil || got.Value != backend.URL || !got.HttpOnly {
		t.Fatalf("cookie sticky absent ou invalide: %+v", resp.Header["Set-Cookie"])
	}
}

func TestSubFilterContentLengthConsistent(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/html")
		_, _ = io.WriteString(w, "hello world")
	}))
	defer backend.Close()

	h := newTestHandler(&router.Route{
		Host:       "app.test",
		Backends:   []router.Backend{{URL: backend.URL}},
		SubFilters: []router.SubFilter{{From: "hello", To: "a much longer greeting"}},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatal(err)
	}
	if string(body) != "a much longer greeting world" {
		t.Fatalf("body = %q", body)
	}
	if cl := resp.Header.Get("Content-Length"); cl != strconv.Itoa(len(body)) {
		t.Fatalf("Content-Length = %q, want %d", cl, len(body))
	}
}

func TestForwardedForNotDuplicated(t *testing.T) {
	var xff, realIP string
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		xff = strings.Join(r.Header.Values("X-Forwarded-For"), "|")
		realIP = r.Header.Get("X-Real-IP")
	}))
	defer backend.Close()

	h := newTestHandler(&router.Route{Host: "app.test", Backends: []router.Backend{{URL: backend.URL}}})
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	req.Header.Set("X-Forwarded-For", "spoofed")
	h.ServeHTTP(httptest.NewRecorder(), req)
	if xff != "203.0.113.9" {
		t.Fatalf("X-Forwarded-For = %q, want a single client IP", xff)
	}
	if realIP != "203.0.113.9" {
		t.Fatalf("X-Real-IP = %q", realIP)
	}
}

func TestForwardedForOmittedWhenDisabled(t *testing.T) {
	var present bool
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, present = r.Header["X-Forwarded-For"]
	}))
	defer backend.Close()

	h := newTestHandler(&router.Route{
		Host:                "app.test",
		Backends:            []router.Backend{{URL: backend.URL}},
		HeadersManipulation: &router.HeadersManipulationConfig{ForwardedHeaders: []string{}},
	})
	req := httptest.NewRequest(http.MethodGet, "http://app.test/", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	h.ServeHTTP(httptest.NewRecorder(), req)
	if present {
		t.Fatal("X-Forwarded-For ne doit pas être envoyé quand forwarded_headers est vide")
	}
}

func TestWebSocketUpgradeOriginCheck(t *testing.T) {
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	}))
	defer backend.Close()

	h := newTestHandler(&router.Route{
		Host:     "app.test",
		Backends: []router.Backend{{URL: backend.URL}},
		CORS:     &router.CORSConfig{AllowedOrigins: []string{"https://app.lab.test"}},
	})
	srv := httptest.NewServer(h)
	defer srv.Close()

	cases := []struct {
		name   string
		origin *string
		deny   bool
	}{
		{"origine listée", ptr("https://app.lab.test"), false},
		{"origine étrangère", ptr("https://evil.test"), true},
		{"origine null", ptr("null"), true},
		{"sans Origin", nil, false},
	}
	for _, c := range cases {
		req, _ := http.NewRequest(http.MethodGet, srv.URL, nil)
		req.Header.Set("Connection", "Upgrade")
		req.Header.Set("Upgrade", "websocket")
		if c.origin != nil {
			req.Header.Set("Origin", *c.origin)
		}
		resp, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", c.name, err)
		}
		resp.Body.Close()
		if got := resp.StatusCode == http.StatusForbidden; got != c.deny {
			t.Errorf("%s: statut %d, refus attendu=%v", c.name, resp.StatusCode, c.deny)
		}
	}
}

func ptr(s string) *string { return &s }
