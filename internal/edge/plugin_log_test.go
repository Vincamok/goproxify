// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/prometheus/client_golang/prometheus/testutil"

	"github.com/vincamok/goproxify/internal/edge/metrics"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type lockedBuf struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *lockedBuf) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.Write(p)
}

func (l *lockedBuf) String() string {
	l.mu.Lock()
	defer l.mu.Unlock()
	return l.b.String()
}

// logPluginServer : serveur de test dont le gestionnaire de plugins journalise dans un tampon lisible.
func logPluginServer(t *testing.T) (*Server, *lockedBuf) {
	t.Helper()
	dir := t.TempDir()
	s := pluginTestServer(t, dir)
	buf := &lockedBuf{}
	s.pluginMgr = plugins.NewManager(s.cache, filepath.Join(dir, "plugins"), slog.New(slog.NewTextHandler(buf, nil)))
	t.Cleanup(func() { s.pluginMgr.Close(context.Background()); s.pluginLog.stop() })
	return s, buf
}

func installLogPlugin(t *testing.T, s *Server, name string, wasm []byte, timeoutMs int) {
	t.Helper()
	sum := sha256.Sum256(wasm)
	err := s.ensurePluginManager().Install(context.Background(), plugins.Package{
		Manifest: plugins.Manifest{Name: name, Version: "1", APIVersion: plugins.APIVersion, Hooks: []string{plugins.HookLog},
			OnError: plugins.OnErrorAllow, Limits: plugins.Limits{TimeoutMs: timeoutMs}},
		SHA256: hex.EncodeToString(sum[:]), Wasm: wasm,
	})
	if err != nil {
		t.Fatal(err)
	}
}

func eventually(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("%s : condition non atteinte", what)
		}
		time.Sleep(10 * time.Millisecond)
	}
}

func TestPluginLog_ReceivesTheFinishedRequest(t *testing.T) {
	s, buf := logPluginServer(t)
	installLogPlugin(t, s, "audit", pt.Log(), 0)

	r := pluginRequest(t, s, router.PluginRef{Name: "audit", Config: map[string]any{"k": "v"}})
	if r.code != 200 || r.body != "contenu du backend" {
		t.Fatalf("la réponse ne doit pas être touchée : %d %q", r.code, r.body)
	}
	eventually(t, "journal du plugin", func() bool { return strings.Contains(buf.String(), "bytes_out") })
	got := buf.String()
	for _, want := range []string{`status`, `200`, `bytes_out`, `18`, `duration_ms`, `/x`, `203.0.113.9`, `Server`} {
		if !strings.Contains(got, want) {
			t.Errorf("l'entrée du hook ne contient pas %q : %s", want, got)
		}
	}
}

// Ce que renvoie un hook log est ignoré : il ne peut ni refuser ni modifier une réponse déjà partie.
func TestPluginLog_DecisionIsIgnored(t *testing.T) {
	s, _ := logPluginServer(t)
	installLogPlugin(t, s, "bavard", pt.Static(`{"action":"deny","status":500,"body":"non"}`), 0)
	r := pluginRequest(t, s, router.PluginRef{Name: "bavard"})
	if r.code != 200 || r.body != "contenu du backend" {
		t.Fatalf("un hook log a changé la réponse : %d %q", r.code, r.body)
	}
	eventually(t, "appel compté", func() bool {
		return testutil.ToFloat64(metrics.PluginLog.Calls.WithLabelValues("bavard", "ok")) >= 1
	})
}

// Le refus d'un autre plugin de la chaîne est une réponse comme une autre pour le journal.
func TestPluginLog_SeesRefusalsFromOtherPlugins(t *testing.T) {
	s, buf := logPluginServer(t)
	installLogPlugin(t, s, "audit2", pt.Log(), 0)
	installPlugin(t, s, "bloque", pt.Static(`{"action":"deny","status":451,"body":"refusé"}`), []string{"request"}, "")

	r := pluginRequest(t, s, router.PluginRef{Name: "audit2"}, router.PluginRef{Name: "bloque"})
	if r.code != 451 {
		t.Fatalf("refus attendu : %d", r.code)
	}
	eventually(t, "journal", func() bool { return strings.Contains(buf.String(), "451") })
}

// Un plugin lent ou en boucle ne retarde pas la requête et un échec est compté.
func TestPluginLog_SlowPluginDoesNotDelayTheRequest(t *testing.T) {
	s, _ := logPluginServer(t)
	loop := pt.Spec{MemMin: 2,
		Funcs:     []pt.Fn{{Typ: 0, Body: pt.I32(1024)}, {Typ: 1, Body: []byte{0x03, 0x40, 0x0c, 0x00, 0x0b, 0x42, 0x00}}},
		ExportsFn: map[string]int{"alloc": 0, "on_log": 1}}.Build()
	installLogPlugin(t, s, "boucle", loop, 300)

	start := time.Now()
	r := pluginRequest(t, s, router.PluginRef{Name: "boucle"})
	if d := time.Since(start); d > 200*time.Millisecond || r.code != 200 {
		t.Fatalf("la requête a attendu le plugin : %v, %d", d, r.code)
	}
	eventually(t, "échec compté", func() bool {
		return testutil.ToFloat64(metrics.PluginLog.Calls.WithLabelValues("boucle", "error")) >= 1
	})
}

// File pleine : les appels en trop sont abandonnés et comptés, jamais accumulés sans borne.
func TestPluginLog_FullQueueDropsCalls(t *testing.T) {
	s, _ := logPluginServer(t)
	loop := pt.Spec{MemMin: 2,
		Funcs:     []pt.Fn{{Typ: 0, Body: pt.I32(1024)}, {Typ: 1, Body: []byte{0x03, 0x40, 0x0c, 0x00, 0x0b, 0x42, 0x00}}},
		ExportsFn: map[string]int{"alloc": 0, "on_log": 1}}.Build()
	installLogPlugin(t, s, "sature", loop, 1000)

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = io.WriteString(w, "ok") }))
	defer backend.Close()
	route := &router.Route{ID: "sature", Host: "app.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}, Plugins: []router.PluginRef{{Name: "sature"}}}
	h := s.handlerForRoute(route, "")
	const n = pluginLogQueueSize + 200
	for i := 0; i < n; i++ {
		req := httptest.NewRequest(http.MethodGet, fmt.Sprintf("http://app.test/%d", i), nil)
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != 200 {
			t.Fatalf("requête %d : %d", i, rr.Code)
		}
	}
	if dropped := testutil.ToFloat64(metrics.PluginLog.Dropped.WithLabelValues("sature")); dropped < 100 {
		t.Fatalf("appels abandonnés : %v (au moins 100 attendus sur %d requêtes)", dropped, n)
	}
}
