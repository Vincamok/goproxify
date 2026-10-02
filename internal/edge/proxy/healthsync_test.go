// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

func hcRoute(id, backend, path string, interval time.Duration) *router.Route {
	return &router.Route{
		ID:          id,
		Backends:    []router.Backend{{URL: backend}},
		HealthCheck: &router.HealthCheckConfig{Path: path, Interval: interval},
	}
}

func TestSyncProbesAndMarksDown(t *testing.T) {
	var sick atomic.Bool
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits.Add(1)
		if sick.Load() {
			w.WriteHeader(http.StatusServiceUnavailable)
		}
	}))
	defer srv.Close()

	h := NewBackendHealth(nil)
	h.Sync([]*router.Route{hcRoute("r1", srv.URL, "/healthz", 20*time.Millisecond)})
	eventually(t, "sondes envoyées", func() bool { return hits.Load() >= 2 })
	sick.Store(true)
	eventually(t, "backend down", func() bool { return !h.IsHealthy(srv.URL) })
	sick.Store(false)
	eventually(t, "backend réintégré", func() bool { return h.IsHealthy(srv.URL) })
}

func TestSyncStopsRemovedBackend(t *testing.T) {
	var hits atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer srv.Close()

	h := NewBackendHealth(nil)
	h.Sync([]*router.Route{hcRoute("r1", srv.URL, "/h", 10*time.Millisecond)})
	eventually(t, "première sonde", func() bool { return hits.Load() >= 1 })
	h.Sync(nil)
	time.Sleep(50 * time.Millisecond)
	n := hits.Load()
	time.Sleep(100 * time.Millisecond)
	if hits.Load() != n {
		t.Fatal("la sonde doit s'arrêter quand la route disparaît")
	}
	if len(h.watched) != 0 || h.Status(srv.URL) != "unknown" {
		t.Fatal("l'état d'un backend retiré doit être purgé")
	}
}

func TestSyncAppliesConfigChange(t *testing.T) {
	var paths atomic.Value
	paths.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { paths.Store(r.URL.Path) }))
	defer srv.Close()

	h := NewBackendHealth(nil)
	h.Sync([]*router.Route{hcRoute("r1", srv.URL, "/a", 10*time.Millisecond)})
	eventually(t, "sonde /a", func() bool { return paths.Load() == "/a" })
	h.Sync([]*router.Route{hcRoute("r1", srv.URL, "/b", 10*time.Millisecond)})
	eventually(t, "sonde /b après modification", func() bool { return paths.Load() == "/b" })
}

func TestSyncSharedBackendPicksMostSpecific(t *testing.T) {
	var paths atomic.Value
	paths.Store("")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { paths.Store(r.URL.Path) }))
	defer srv.Close()

	implicit := &router.Route{ID: "a", Backends: []router.Backend{{URL: srv.URL}}}
	slow := hcRoute("b", srv.URL, "/slow", time.Hour)
	fast := hcRoute("c", srv.URL, "/fast", 10*time.Millisecond)

	h := NewBackendHealth(nil)
	h.Sync([]*router.Route{implicit, slow, fast})
	eventually(t, "config la plus réactive retenue", func() bool { return paths.Load() == "/fast" })
	if got := h.watched[srv.URL].cfg.path; got != "/fast" {
		t.Fatalf("path=%s", got)
	}
}
