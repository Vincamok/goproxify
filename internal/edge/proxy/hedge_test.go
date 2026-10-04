package proxy

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func hedgeHandler(t *testing.T, slow, fast http.HandlerFunc, hc *router.HedgeConfig) *Handler {
	t.Helper()
	s1, s2 := httptest.NewServer(slow), httptest.NewServer(fast)
	t.Cleanup(s1.Close)
	t.Cleanup(s2.Close)
	route := &router.Route{
		ID: "hedge", Host: "hedge.test", Type: router.RouteHTTP, Hedge: hc,
		Backends: []router.Backend{{URL: s1.URL}, {URL: s2.URL}},
	}
	return NewHandler(route, NewBackendHealth(slog.Default()), NewAgentMetricsStore(), NewPeerRegistry(), slog.Default())
}

func TestHedgeFastBackendWinsOverSlowOne(t *testing.T) {
	var slowHit atomic.Int32
	h := hedgeHandler(t,
		func(w http.ResponseWriter, r *http.Request) {
			slowHit.Add(1)
			select {
			case <-time.After(2 * time.Second):
			case <-r.Context().Done():
				return
			}
			_, _ = w.Write([]byte("slow"))
		},
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fast")) },
		&router.HedgeConfig{DelayMs: 50})
	// Le balancer round-robin peut préférer l'un ou l'autre : dans les deux cas le résultat doit être « fast ».
	for i := 0; i < 4; i++ {
		start := time.Now()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://hedge.test/", nil))
		body, _ := io.ReadAll(rec.Result().Body)
		if rec.Code != 200 || strings.TrimSpace(string(body)) != "fast" {
			t.Fatalf("requête %d : code=%d corps=%q", i, rec.Code, body)
		}
		if d := time.Since(start); d > time.Second {
			t.Fatalf("requête %d : %v, la tentative lente n'a pas été doublée", i, d)
		}
	}
	if slowHit.Load() == 0 {
		t.Fatal("le backend lent n'a jamais été sollicité")
	}
}

func TestHedgeSkippedForPOST(t *testing.T) {
	var hits atomic.Int32
	count := func(w http.ResponseWriter, r *http.Request) { hits.Add(1); _, _ = w.Write([]byte("ok")) }
	h := hedgeHandler(t, count, count, &router.HedgeConfig{DelayMs: 1})
	req := httptest.NewRequest("POST", "http://hedge.test/", strings.NewReader("x"))
	if h.hedgeable(req) {
		t.Fatal("POST doublable")
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != 200 || hits.Load() != 1 {
		t.Fatalf("code=%d hits=%d", rec.Code, hits.Load())
	}
}

func TestHedgeFailoverWhenFirstFails(t *testing.T) {
	h := hedgeHandler(t,
		func(w http.ResponseWriter, r *http.Request) {
			hj, _ := w.(http.Hijacker)
			c, _, _ := hj.Hijack()
			c.Close()
		},
		func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("fast")) },
		&router.HedgeConfig{DelayMs: 5000})
	for i := 0; i < 3; i++ {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest("GET", "http://hedge.test/", nil))
		if rec.Code != 200 || !strings.Contains(rec.Body.String(), "fast") {
			t.Fatalf("requête %d : code=%d corps=%q", i, rec.Code, rec.Body.String())
		}
	}
}
