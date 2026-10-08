// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func ipCode(t *testing.T, cfg *router.IPFilterConfig, remote string) int {
	t.Helper()
	h := IPFilter(cfg)(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusOK) }))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = remote
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec.Code
}

func TestIPFilter_AllowAndDeny(t *testing.T) {
	allow := &router.IPFilterConfig{Mode: "allow", CIDRs: []string{"10.0.0.0/8", "203.0.113.7"}}
	deny := &router.IPFilterConfig{Mode: "deny", CIDRs: []string{"10.0.0.0/8", "2001:db8::1"}}
	for _, c := range []struct {
		name   string
		cfg    *router.IPFilterConfig
		remote string
		want   int
	}{
		{"allow: dans le CIDR", allow, "10.1.2.3:1000", 200},
		{"allow: IP seule", allow, "203.0.113.7:1000", 200},
		{"allow: hors liste", allow, "198.51.100.1:1000", 403},
		{"deny: dans le CIDR", deny, "10.9.9.9:1000", 403},
		{"deny: IPv6 seule", deny, "[2001:db8::1]:1000", 403},
		{"deny: hors liste", deny, "198.51.100.1:1000", 200},
		{"nil = désactivé", nil, "10.0.0.1:1", 200},
		{"liste vide = désactivé", &router.IPFilterConfig{Mode: "allow"}, "198.51.100.1:1", 200},
	} {
		if got := ipCode(t, c.cfg, c.remote); got != c.want {
			t.Errorf("%s : %d (attendu %d)", c.name, got, c.want)
		}
	}
}

// Un mode mal écrit ouvrait le filtre à tout le monde (ni allow ni deny ⇒ requête transmise).
func TestIPFilter_UnknownModeFailsClosed(t *testing.T) {
	for _, mode := range []string{"", "alow", "block", "whitelist"} {
		if got := ipCode(t, &router.IPFilterConfig{Mode: mode, CIDRs: []string{"10.0.0.0/8"}}, "198.51.100.1:1"); got != 403 {
			t.Errorf("mode %q : %d (attendu 403)", mode, got)
		}
	}
}

func TestIPFilter_ModeIsCaseAndSpaceInsensitive(t *testing.T) {
	if got := ipCode(t, &router.IPFilterConfig{Mode: " Allow ", CIDRs: []string{"10.0.0.0/8"}}, "198.51.100.1:1"); got != 403 {
		t.Errorf("Allow hors liste : %d", got)
	}
	if got := ipCode(t, &router.IPFilterConfig{Mode: "DENY", CIDRs: []string{" 10.0.0.0/8 "}}, "10.1.1.1:1"); got != 403 {
		t.Errorf("DENY dans la liste : %d", got)
	}
}

// Une adresse client illisible n'est jamais « autorisée ».
func TestIPFilter_UnparseableClientNeverAllowed(t *testing.T) {
	if got := ipCode(t, &router.IPFilterConfig{Mode: "allow", CIDRs: []string{"0.0.0.0/0"}}, "not-an-ip"); got != 403 {
		t.Errorf("allow 0.0.0.0/0 avec client illisible : %d", got)
	}
}

// Un en-tête X-Forwarded-For d'un client direct ne change pas l'adresse évaluée.
func TestIPFilter_IgnoresForgedForwardedFor(t *testing.T) {
	h := IPFilter(&router.IPFilterConfig{Mode: "allow", CIDRs: []string{"10.0.0.0/8"}})(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {}))
	req := httptest.NewRequest(http.MethodGet, "/", nil)
	req.RemoteAddr = "198.51.100.1:1"
	req.Header.Set("X-Forwarded-For", "10.0.0.1")
	req.Header.Set("CF-Connecting-IP", "10.0.0.1")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 403 {
		t.Fatalf("XFF forgé accepté : %d", rec.Code)
	}
}
