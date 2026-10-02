// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// burst lance n requêtes simultanées, chacune résolvant sa chaîne via handlerForRoute,
// et retourne le nombre de 503 reçus une fois les 2 premières bloquées dans le backend.
func burst(t *testing.T, s *Server, route *router.Route, n int, entered <-chan struct{}, release chan struct{}, wantAccepted int) (accepted, rejected int) {
	t.Helper()
	var acc, rej atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			rr := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodGet, "http://"+route.Host+"/", nil)
			s.handlerForRoute(route, "/").ServeHTTP(rr, req)
			if rr.Code == http.StatusServiceUnavailable {
				rej.Add(1)
			} else {
				acc.Add(1)
			}
		}()
	}
	close(start)
	for i := 0; i < wantAccepted; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			t.Fatalf("seulement %d requêtes ont atteint le backend, %d attendues", i, wantAccepted)
		}
	}
	// Laisse le temps aux requêtes en excès d'être rejetées avant de libérer le backend.
	time.Sleep(200 * time.Millisecond)
	close(release)
	wg.Wait()
	return int(acc.Load()), int(rej.Load())
}

func TestHandlerForRouteConcurrentFirstUseRespectsBackpressure(t *testing.T) {
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	defer backend.Close()

	s := testEdgeServer()
	s.health = proxy.NewBackendHealth(s.log.Logger())
	route := &router.Route{
		ID:           "race-first-use",
		Host:         "race-first-use.test",
		Type:         router.RouteHTTP,
		Backends:     []router.Backend{{URL: backend.URL}},
		Backpressure: &router.BackpressureConfig{MaxInflight: 2},
	}

	acc, rej := burst(t, s, route, 6, entered, release, 2)
	if acc != 2 || rej != 4 {
		t.Fatalf("acceptées=%d rejetées=%d, attendu 2/4", acc, rej)
	}
	// Une seule chaîne dans le cache malgré la rafale sur une route neuve.
	n := 0
	s.dispatchHandlers.Range(func(_, _ any) bool { n++; return true })
	if n != 1 {
		t.Fatalf("%d entrées de cache, attendu 1", n)
	}
}

func TestBackpressureStateSurvivesDispatchRebuild(t *testing.T) {
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		entered <- struct{}{}
		<-release
	}))
	defer backend.Close()

	s := testEdgeServer()
	s.health = proxy.NewBackendHealth(s.log.Logger())
	route := &router.Route{
		ID:           "race-rebuild",
		Host:         "race-rebuild.test",
		Type:         router.RouteHTTP,
		Backends:     []router.Backend{{URL: backend.URL}},
		Backpressure: &router.BackpressureConfig{MaxInflight: 2},
	}

	// Deux requêtes occupent les slots, puis la route est reconstruite : les
	// suivantes doivent toujours voir les 2 slots pris.
	var wg sync.WaitGroup
	for i := 0; i < 2; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			s.handlerForRoute(route, "/").ServeHTTP(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "http://"+route.Host+"/", nil))
		}()
	}
	for i := 0; i < 2; i++ {
		<-entered
	}
	s.invalidateDispatchCache()
	rr := httptest.NewRecorder()
	s.handlerForRoute(route, "/").ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://"+route.Host+"/", nil))
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d après reconstruction, attendu 503 (slots conservés)", rr.Code)
	}
	close(release)
	wg.Wait()
}
