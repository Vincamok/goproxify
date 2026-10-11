// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Mesure de la chaîne de plugins sous charge, avec les modules d'exemple compilés par TinyGo : une vraie passerelle
// (handlerForRoute, tout le middleware de la route), un vrai backend HTTP, des clients concurrents en keep-alive.

func installExample(t testing.TB, s *Server, name string) {
	t.Helper()
	dir := filepath.Join("..", "..", "examples", "plugins", name)
	wasm, err := os.ReadFile(filepath.Join(dir, name+".wasm"))
	if err != nil {
		t.Skipf("module d'exemple absent : %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m plugins.Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	sum := sha256.Sum256(wasm)
	if err := s.ensurePluginManager().Install(context.Background(), plugins.Package{Manifest: m, SHA256: hex.EncodeToString(sum[:]), Wasm: wasm}); err != nil {
		t.Fatal(err)
	}
}

// loadBackend répond avec un corps de 3 Kio qui contient le texte à masquer.
func loadBackend(t testing.TB) *httptest.Server {
	body := strings.Repeat("0123456789 SECRET ", 170)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "text/plain")
		_, _ = io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

type loadScenario struct {
	name string
	refs []router.PluginRef
	// check valide la réponse reçue par le client.
	check func(code int, body string) error
}

func loadScenarios() []loadScenario {
	ok := func(code int, body string) error {
		if code != 200 {
			return fmt.Errorf("status %d", code)
		}
		return nil
	}
	return []loadScenario{
		{"sans plugin", nil, ok},
		{"path-guard", []router.PluginRef{{Name: "path-guard", Config: map[string]any{"blocked_prefix": "/interdit"}}}, ok},
		{"rate-guard (kv)", []router.PluginRef{{Name: "rate-guard", Config: map[string]any{"limit": "1000000000"}}}, ok},
		{"body-redact (3 Kio)", []router.PluginRef{{Name: "body-redact", Config: map[string]any{"needle": "SECRET"}}}, func(code int, body string) error {
			if code != 200 || strings.Contains(body, "SECRET") || !strings.Contains(body, "***") {
				return fmt.Errorf("status %d, corps non masqué", code)
			}
			return nil
		}},
		{"3 plugins empilés", []router.PluginRef{
			{Name: "path-guard", Config: map[string]any{"blocked_prefix": "/interdit"}},
			{Name: "rate-guard", Config: map[string]any{"limit": "1000000000"}},
			{Name: "body-redact", Config: map[string]any{"needle": "SECRET"}},
		}, func(code int, body string) error {
			if code != 200 || strings.Contains(body, "SECRET") {
				return fmt.Errorf("status %d, corps non masqué", code)
			}
			return nil
		}},
	}
}

func loadServer(t testing.TB) (*Server, *httptest.Server) {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GPX_PLUGINS_DIR", filepath.Join(dir, "plugins"))
	s := &Server{
		log:   edgelog.New("error", "text", ""),
		table: &router.Table{},
		cache: edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
	}
	s.health = proxy.NewBackendHealth(s.log.Logger())
	t.Cleanup(func() { s.ensurePluginManager().Close(context.Background()) })
	for _, n := range []string{"path-guard", "rate-guard", "body-redact"} {
		installExample(t, s, n)
	}
	return s, loadBackend(t)
}

func routeFor(s *Server, backend *httptest.Server, id string, refs []router.PluginRef) *httptest.Server {
	route := &router.Route{ID: id, Host: "app.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}, Plugins: refs}
	front := httptest.NewServer(s.handlerForRoute(route, ""))
	return front
}

// Chaque scénario sert des réponses correctes sous concurrence : pas de mélange entre appels (instance neuve par
// appel), pas de corps tronqué, pas d'erreur.
func TestPluginLoad_CorrectUnderConcurrency(t *testing.T) {
	s, backend := loadServer(t)
	for i, sc := range loadScenarios() {
		front := routeFor(s, backend, fmt.Sprintf("load-ok-%d", i), sc.refs)
		var wg sync.WaitGroup
		var bad atomic.Int64
		var first atomic.Value
		client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: 32}}
		for w := 0; w < 16; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for k := 0; k < 25; k++ {
					resp, err := client.Get(front.URL + "/page")
					if err != nil {
						bad.Add(1)
						first.CompareAndSwap(nil, err.Error())
						continue
					}
					b, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if err := sc.check(resp.StatusCode, string(b)); err != nil {
						bad.Add(1)
						first.CompareAndSwap(nil, err.Error())
					}
				}
			}()
		}
		wg.Wait()
		front.Close()
		if bad.Load() != 0 {
			t.Errorf("%s : %d réponses invalides sur 400 (première : %v)", sc.name, bad.Load(), first.Load())
		}
	}
}

// BenchmarkPluginChain : coût CPU par requête, en parallèle sur tous les cœurs, sans réseau entre le client et la
// passerelle (le backend reste un vrai serveur HTTP sur la boucle locale).
func BenchmarkPluginChain(b *testing.B) {
	s, backend := loadServer(b)
	for i, sc := range loadScenarios() {
		route := &router.Route{ID: fmt.Sprintf("bench-%d", i), Host: "app.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}, Plugins: sc.refs}
		h := s.handlerForRoute(route, "")
		b.Run(sc.name, func(b *testing.B) {
			b.ReportAllocs()
			b.RunParallel(func(pb *testing.PB) {
				for pb.Next() {
					req := httptest.NewRequest(http.MethodGet, "http://app.test/page", nil)
					req.RemoteAddr = "203.0.113.9:1234"
					rr := httptest.NewRecorder()
					h.ServeHTTP(rr, req)
					if rr.Code != 200 {
						b.Fatalf("status %d", rr.Code)
					}
				}
			})
		})
	}
}

// TestPluginLoad_Report : débit et latences avec des clients concurrents en keep-alive, sur le réseau local. Long
// (quelques secondes par scénario) : lancé seulement avec GPX_LOAD=1 ; GPX_LOAD_SECONDS et GPX_LOAD_CLIENTS règlent
// la durée et la concurrence.
//
//	GPX_LOAD=1 go test ./internal/edge -run TestPluginLoad_Report -v -count=1
func TestPluginLoad_Report(t *testing.T) {
	if os.Getenv("GPX_LOAD") == "" {
		t.Skip("mesure en charge : GPX_LOAD=1 pour la lancer")
	}
	seconds, clients := 3, 64
	if v, err := strconv.Atoi(os.Getenv("GPX_LOAD_SECONDS")); err == nil && v > 0 {
		seconds = v
	}
	if v, err := strconv.Atoi(os.Getenv("GPX_LOAD_CLIENTS")); err == nil && v > 0 {
		clients = v
	}
	s, backend := loadServer(t)
	t.Logf("%d clients, %d s par scénario", clients, seconds)
	t.Logf("%-22s %10s %9s %9s %9s %9s", "scénario", "req/s", "p50", "p95", "p99", "erreurs")
	for i, sc := range loadScenarios() {
		front := routeFor(s, backend, fmt.Sprintf("load-rep-%d", i), sc.refs)
		client := &http.Client{Transport: &http.Transport{MaxIdleConnsPerHost: clients, MaxConnsPerHost: clients}}
		var mu sync.Mutex
		var lat []time.Duration
		var errs atomic.Int64
		stop := time.Now().Add(time.Duration(seconds) * time.Second)
		var wg sync.WaitGroup
		start := time.Now()
		for w := 0; w < clients; w++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				var mine []time.Duration
				for time.Now().Before(stop) {
					t0 := time.Now()
					resp, err := client.Get(front.URL + "/page")
					if err != nil {
						errs.Add(1)
						continue
					}
					b, _ := io.ReadAll(resp.Body)
					resp.Body.Close()
					if sc.check(resp.StatusCode, string(b)) != nil {
						errs.Add(1)
					}
					mine = append(mine, time.Since(t0))
				}
				mu.Lock()
				lat = append(lat, mine...)
				mu.Unlock()
			}()
		}
		wg.Wait()
		elapsed := time.Since(start).Seconds()
		front.Close()
		sort.Slice(lat, func(a, b int) bool { return lat[a] < lat[b] })
		pct := func(p float64) time.Duration {
			if len(lat) == 0 {
				return 0
			}
			return lat[int(float64(len(lat)-1)*p)]
		}
		t.Logf("%-22s %10.0f %9s %9s %9s %9d", sc.name, float64(len(lat))/elapsed,
			pct(0.50).Round(time.Microsecond), pct(0.95).Round(time.Microsecond), pct(0.99).Round(time.Microsecond), errs.Load())
		if errs.Load() != 0 {
			t.Errorf("%s : %d erreurs", sc.name, errs.Load())
		}
	}
}
