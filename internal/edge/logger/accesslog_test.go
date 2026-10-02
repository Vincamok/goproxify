// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logger

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
	"time"
)

func TestStripHostPort(t *testing.T) {
	cases := map[string]string{
		"example.com":          "example.com",
		"example.com:443":      "example.com",
		"127.0.0.1:8080":       "127.0.0.1",
		"[2001:db8::1]:443":    "2001:db8::1",
		"[2001:db8::1]":        "2001:db8::1",
	}
	for in, want := range cases {
		if got := stripHostPort(in); got != want {
			t.Errorf("stripHostPort(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAccessLoggerForwarder(t *testing.T) {
	al := NewAccessLogger("")
	var (
		mu   sync.Mutex
		got  []ShipEntry
		done = make(chan struct{})
	)
	al.SetForwarder(func(batch []ShipEntry) {
		mu.Lock()
		got = append(got, batch...)
		n := len(got)
		mu.Unlock()
		if n < 3 {
			return
		}
		select {
		case <-done:
		default:
			close(done)
		}
	})

	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok"))
	}))
	// Sans protection, anonymisée, pseudonymisée.
	for _, mode := range [][2]bool{{false, false}, {true, false}, {false, true}} {
		al.SetIPProtection(mode[0], mode[1])
		req := httptest.NewRequest(http.MethodGet, "https://app.example.com:443/api/ping", nil)
		req.Host = "app.example.com:443"
		req.RemoteAddr = "203.0.113.42:51234"
		req.Header.Set("Referer", "https://ref.example/")
		h.ServeHTTP(httptest.NewRecorder(), req)
	}

	select {
	case <-done:
	case <-time.After(8 * time.Second):
		t.Fatal("timeout waiting for forwarder flush")
	}

	mu.Lock()
	defer mu.Unlock()
	for i, want := range []struct {
		ip, realIP string
		truncated  bool
	}{
		{"203.0.113.42", "", false},
		{"203.0.113.0", "", true},
		{"203.0.113.0", "203.0.113.42", true},
	} {
		if s := got[i]; s.IP != want.ip || s.RealIP != want.realIP || s.IPTruncated != want.truncated {
			t.Errorf("entrée %d : ip=%q real_ip=%q ip_truncated=%v, attendu %q %q %v",
				i, s.IP, s.RealIP, s.IPTruncated, want.ip, want.realIP, want.truncated)
		}
	}
	e := got[0]
	if e.Domain != "app.example.com" {
		t.Errorf("domain=%q want app.example.com", e.Domain)
	}
	if e.Status != 200 {
		t.Errorf("status=%d want 200", e.Status)
	}
	if e.Component != "edge" {
		t.Errorf("component=%q want edge", e.Component)
	}
	if e.Path != "/api/ping" {
		t.Errorf("path=%q want /api/ping", e.Path)
	}
	if e.Referrer != "https://ref.example/" {
		t.Errorf("referrer=%q", e.Referrer)
	}
}

func TestIPFieldsAnonymizeWinsOverPseudonymize(t *testing.T) {
	const ip = "203.0.113.42"
	cases := []struct {
		anon, pseudo      bool
		wantLog, wantShip string
	}{
		{false, false, ip, ""},
		{true, false, "203.0.113.0", ""},
		{false, true, "203.0.113.0", ip},
		{true, true, "203.0.113.0", ""},
	}
	for _, c := range cases {
		logIP, shipIP := ipFields(ip, c.anon, c.pseudo)
		if logIP != c.wantLog || shipIP != c.wantShip {
			t.Errorf("anon=%v pseudo=%v: got (%q, %q) want (%q, %q)", c.anon, c.pseudo, logIP, shipIP, c.wantLog, c.wantShip)
		}
	}
}

func TestAccessLoggerSkipsInternal(t *testing.T) {
	al := NewAccessLogger("")
	var got int
	al.SetForwarder(func(batch []ShipEntry) {
		got += len(batch)
	})
	h := al.Middleware(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	}))
	req := httptest.NewRequest(http.MethodGet, "http://edge/internal/v1/health", nil)
	req.Host = "edge"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	time.Sleep(200 * time.Millisecond)
	if got != 0 {
		t.Errorf("internal path should not ship, got %d", got)
	}
}
