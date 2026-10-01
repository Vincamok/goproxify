// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	"github.com/vincamok/goproxify/internal/edge/bansdb"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// newSentinelGateway construit une passerelle sur le volume dir, sans aucun Admin connecté.
// Deux appels sur le même dir simulent un redémarrage.
func newSentinelGateway(t *testing.T, dir string, routes ...*router.Route) *Server {
	t.Helper()
	t.Setenv("GPX_THREAT_CONFIG_PATH", filepath.Join(dir, "threat-config.gpx"))
	db, err := bansdb.Open(filepath.Join(dir, "bansdb"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	discard := slog.New(slog.NewTextHandler(io.Discard, nil))
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
		wsHub:        edgews.NewHub("", discard),
	}
	if err := s.table.Replace(routes); err != nil {
		t.Fatal(err)
	}
	s.threatEngine = threat.New(discard, s.threatBanCallback())
	return s
}

func requestFrom(s *Server, ip, path string) int {
	req := httptest.NewRequest(http.MethodGet, "http://app.example.test"+path, nil)
	req.RemoteAddr = ip + ":40000"
	rec := httptest.NewRecorder()
	s.dispatch(rec, req)
	return rec.Code
}

func TestSentinelBanBlocksNextRequestsAndSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	const ip = "203.0.113.60"
	s := newSentinelGateway(t, dir)
	s.threatEngine.UpdateConfig(threat.Config{
		Enabled:     true,
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		BanDuration: threat.Duration{Duration: time.Hour},
	})

	if code := requestFrom(s, ip, "/wp-login.php"); code != http.StatusForbidden {
		t.Fatalf("la requête qui déclenche Sentinel doit être refusée, reçu %d", code)
	}
	if code := requestFrom(s, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("le ban Sentinel doit bloquer les requêtes suivantes sans l'Admin, reçu %d", code)
	}
	rows, err := s.bansDB.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "threat-"+ip || rows[0].Source != "threat" || rows[0].ExpiresAt == nil ||
		time.Until(*rows[0].ExpiresAt) < 50*time.Minute {
		t.Fatalf("ban Sentinel persisté attendu (durée de la config), reçu %+v", rows)
	}
	if n, _ := s.bansDB.RecentBanCount(time.Now().Add(-24*time.Hour), "threat"); n != 1 {
		t.Fatalf("le ban doit être historisé pour les règles automatiques, reçu %d", n)
	}

	_ = s.bansDB.Close()
	restarted := newSentinelGateway(t, dir)
	restarted.loadBansFromDisk()
	if code := requestFrom(restarted, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("le ban Sentinel doit survivre à un redémarrage sans l'Admin, reçu %d", code)
	}
	if code := requestFrom(restarted, "203.0.113.61", "/"); code != http.StatusNotFound {
		t.Fatalf("une autre IP ne doit pas être bloquée, reçu %d", code)
	}
}

func TestPushedSentinelConfigIsReloadedAfterRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	const scanner, routeWhitelisted, cfgWhitelisted = "203.0.113.70", "198.51.100.7", "198.51.100.8"
	route := &router.Route{ID: "app", Host: "app.example.test", SentinelWhitelist: []string{routeWhitelisted}}
	s := newSentinelGateway(t, dir, route)
	msg, err := edgews.NewMessage(0, edgews.TypePushThreatConfig, threat.Config{
		Enabled:     true,
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		Whitelist:   threat.Whitelist{IPs: []string{cfgWhitelisted}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.handleWSAdminMessage("admin", msg); err != nil {
		t.Fatal(err)
	}
	if !s.threatEngine.WhitelistedIP(routeWhitelisted) {
		t.Fatal("la config poussée ne doit pas effacer la liste blanche des routes")
	}
	raw, err := os.ReadFile(filepath.Join(dir, "threat-config.gpx"))
	if err != nil {
		t.Fatalf("la config poussée doit être copiée sur le volume : %v", err)
	}
	if strings.Contains(string(raw), "wp-login") {
		t.Fatal("la copie locale de la config doit être chiffrée")
	}

	_ = s.bansDB.Close()
	restarted := newSentinelGateway(t, dir, route)
	restarted.loadThreatConfigFromDisk()
	if !restarted.threatEngine.Enabled() {
		t.Fatal("Sentinel doit redémarrer actif sur sa dernière config, sans l'Admin")
	}
	if code := requestFrom(restarted, scanner, "/wp-login.php"); code != http.StatusForbidden {
		t.Fatalf("la liste personnalisée doit s'appliquer après redémarrage, reçu %d", code)
	}
	if !restarted.threatEngine.WhitelistedIP(cfgWhitelisted) || !restarted.threatEngine.WhitelistedIP(routeWhitelisted) {
		t.Fatal("listes blanches de la config et des routes attendues après redémarrage")
	}
}
