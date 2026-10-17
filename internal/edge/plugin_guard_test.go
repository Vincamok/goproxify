// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge/bansdb"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// newGuardGateway est une passerelle sans Admin avec un plugin « coraza » qui refuse tout (403) et, selon
// detector, se déclare ou non plugin de détection.
func newGuardGateway(t *testing.T, dir string, detector bool) *Server {
	t.Helper()
	t.Setenv("GPX_PLUGINS_DIR", filepath.Join(dir, "plugins"))
	db, err := bansdb.Open(filepath.Join(dir, "bansdb"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	cfg := &config.EdgeConfig{}
	cfg.Identity.NodeName = "frontal"
	s := &Server{
		cfg:          cfg,
		log:          edgelog.New("error", "text", ""),
		bansDB:       db,
		banStore:     router.NewBanStore(),
		profileStore: router.NewIPProfileStore(),
		table:        &router.Table{},
		cache:        edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
		wsHub:        edgews.NewHub("", slog.New(slog.NewTextHandler(io.Discard, nil))),
	}
	s.health = proxy.NewBackendHealth(s.log.Logger())
	t.Cleanup(func() { s.ensurePluginManager().Close(context.Background()) })

	wasm := pt.Static(`{"action":"deny","status":403,"body":"refusé"}`)
	sum := sha256.Sum256(wasm)
	err = s.ensurePluginManager().Install(context.Background(), plugins.Package{
		Manifest: plugins.Manifest{Name: "coraza", Version: "1", APIVersion: plugins.APIVersion, Hooks: []string{"request"}, Detector: detector},
		SHA256:   hex.EncodeToString(sum[:]), Wasm: wasm,
	})
	if err != nil {
		t.Fatal(err)
	}
	return s
}

// guardRequest envoie une requête depuis ip sur une route qui porte le plugin avec cfg, derrière le journal d'accès.
func guardRequest(t *testing.T, s *Server, al *edgelog.AccessLogger, ip string, cfg map[string]any) int {
	t.Helper()
	route := &router.Route{
		ID: t.Name(), Host: "app.test", Type: router.RouteHTTP,
		Backends: []router.Backend{{URL: "http://127.0.0.1:1"}},
		Plugins:  []router.PluginRef{{Name: "coraza", Config: cfg}},
	}
	h := s.handlerForRoute(route, "")
	if al != nil {
		h = al.Middleware(h)
	}
	req := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
	req.RemoteAddr = ip + ":1234"
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	return rr.Code
}

func activeBanSources(t *testing.T, s *Server) []string {
	t.Helper()
	rows, err := s.bansDB.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, r := range rows {
		out = append(out, r.Source+" "+r.IP+" "+r.Reason)
	}
	return out
}

func TestPluginGuard_BansAfterThresholdWithPluginSource(t *testing.T) {
	s := newGuardGateway(t, t.TempDir(), true)
	cfg := map[string]any{"ban_after": float64(3), "ban_duration_sec": float64(600)}

	for i := range 2 {
		if code := guardRequest(t, s, nil, "203.0.113.9", cfg); code != 403 {
			t.Fatalf("refus %d : %d", i+1, code)
		}
		if blocked, _ := s.banStore.CheckBlocked("203.0.113.9"); blocked {
			t.Fatalf("banni dès le refus %d, seuil 3", i+1)
		}
	}
	guardRequest(t, s, nil, "203.0.113.9", cfg)

	blocked, reason := s.banStore.CheckBlocked("203.0.113.9")
	if !blocked || reason != "plugin:coraza: coraza: trop de refus" {
		t.Fatalf("après 3 refus : blocked=%v reason=%q", blocked, reason)
	}
	if got := activeBanSources(t, s); len(got) != 1 || got[0] != "plugin:coraza 203.0.113.9 coraza: trop de refus" {
		t.Errorf("ban persisté localement (survit à un redémarrage sans l'Admin) : %v", got)
	}
	if blocked, _ := s.banStore.CheckBlocked("203.0.113.10"); blocked {
		t.Error("une autre IP ne doit pas être bannie")
	}
}

func TestPluginGuard_NeverBansWithoutOptIn(t *testing.T) {
	cases := map[string]struct {
		detector bool
		cfg      map[string]any
		ip       string
	}{
		"ban_after absent":     {true, nil, "203.0.113.9"},
		"ban_after à 0":        {true, map[string]any{"ban_after": float64(0)}, "203.0.113.9"},
		"plugin non détecteur": {false, map[string]any{"ban_after": float64(1)}, "203.0.113.9"},
		"réseau privé":         {true, map[string]any{"ban_after": float64(1)}, "10.0.0.5"},
		"valeur illisible":     {true, map[string]any{"ban_after": "beaucoup"}, "203.0.113.9"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			s := newGuardGateway(t, t.TempDir(), c.detector)
			for range 5 {
				if code := guardRequest(t, s, nil, c.ip, c.cfg); code != 403 {
					t.Fatalf("le refus du plugin doit rester un 403, reçu %d", code)
				}
			}
			if got := activeBanSources(t, s); len(got) != 0 {
				t.Errorf("bans inattendus : %v", got)
			}
		})
	}
}

func TestPluginGuard_ThresholdFromDockerLabelString(t *testing.T) {
	s := newGuardGateway(t, t.TempDir(), true)
	for range 2 {
		guardRequest(t, s, nil, "198.51.100.7", map[string]any{"ban_after": "2"})
	}
	if blocked, _ := s.banStore.CheckBlocked("198.51.100.7"); !blocked {
		t.Fatal("ban_after fourni en chaîne (label Docker) ignoré")
	}
}

func TestPluginGuard_WhitelistedIPIsNeverBanned(t *testing.T) {
	s := newGuardGateway(t, t.TempDir(), true)
	s.profileStore.Replace([]*router.IPProfile{{ID: router.WhitelistProfileID, Mode: "allow", CIDRs: []string{"198.51.100.0/24"}}})
	for range 5 {
		guardRequest(t, s, nil, "198.51.100.7", map[string]any{"ban_after": float64(1)})
	}
	if got := activeBanSources(t, s); len(got) != 0 {
		t.Errorf("IP en liste blanche bannie : %v", got)
	}
}

func TestPluginGuard_DenialReachesAccessLog(t *testing.T) {
	s := newGuardGateway(t, t.TempDir(), true)
	al := edgelog.NewAccessLogger("")
	got := make(chan edgelog.ShipEntry, 4)
	al.SetForwarder(func(batch []edgelog.ShipEntry) {
		for _, e := range batch {
			got <- e
		}
	})
	guardRequest(t, s, al, "203.0.113.9", nil)

	select {
	case e := <-got:
		if !slices.Equal(e.WAFMatches, []string{"coraza"}) || e.Status != 403 {
			t.Errorf("entrée du journal : status=%d waf_matches=%v", e.Status, e.WAFMatches)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("aucune entrée expédiée")
	}
}

func TestPluginGuard_NonDetectorDenialIsNotAWAFMatch(t *testing.T) {
	s := newGuardGateway(t, t.TempDir(), false)
	al := edgelog.NewAccessLogger("")
	got := make(chan edgelog.ShipEntry, 4)
	al.SetForwarder(func(batch []edgelog.ShipEntry) {
		for _, e := range batch {
			got <- e
		}
	})
	guardRequest(t, s, al, "203.0.113.9", nil)

	select {
	case e := <-got:
		if len(e.WAFMatches) != 0 {
			t.Errorf("un plugin de contrôle d'accès n'est pas un détecteur : waf_matches=%v", e.WAFMatches)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("aucune entrée expédiée")
	}
}

func TestPluginGuard_WindowSlides(t *testing.T) {
	var g pluginGuard
	t0 := time.Unix(1_000_000, 0)
	win := 10 * time.Second
	for i, at := range []time.Duration{0, 4 * time.Second, 8 * time.Second} {
		if n := g.record("k", win, t0.Add(at)); n != i+1 {
			t.Fatalf("refus %d : compte %d", i+1, n)
		}
	}
	if n := g.record("k", win, t0.Add(13*time.Second)); n != 3 {
		t.Errorf("à +13 s le premier refus est sorti de la fenêtre : compte %d, attendu 3", n)
	}
	g.reset("k")
	if n := g.record("k", win, t0.Add(14*time.Second)); n != 1 {
		t.Errorf("après reset : compte %d", n)
	}
}

func TestPluginGuard_SweepsStaleKeys(t *testing.T) {
	var g pluginGuard
	t0 := time.Unix(1_000_000, 0)
	for i := range pluginGuardSweepAbove + 10 {
		g.record(fmt.Sprintf("p\x00%d", i), time.Second, t0)
	}
	g.record("p\x00neuf", time.Second, t0.Add(time.Minute))
	if n := len(g.hits); n > 5 {
		t.Errorf("%d clés conservées, les expirées devaient être balayées", n)
	}
}

func TestConfigInt(t *testing.T) {
	cfg := map[string]any{"a": float64(5), "b": 7, "c": " 9 ", "d": "x", "e": nil}
	for key, want := range map[string]int{"a": 5, "b": 7, "c": 9, "d": 42, "e": 42, "absent": 42} {
		if got := configInt(cfg, key, 42); got != want {
			t.Errorf("configInt(%q)=%d, attendu %d", key, got, want)
		}
	}
}
