// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
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
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// newEphorGateway construit une passerelle sur le volume dir, sans aucun Admin connecté.
// Deux appels sur le même dir simulent un redémarrage.
func newEphorGateway(t *testing.T, dir string, routes ...*router.Route) *Server {
	t.Helper()
	t.Setenv("GPX_THREAT_CONFIG_PATH", filepath.Join(dir, "threat-config.gpx"))
	t.Setenv("GPX_THREAT_STATE_PATH", filepath.Join(dir, "threat-state.gpx"))
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

func TestEphorBanBlocksNextRequestsAndSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	const ip = "203.0.113.60"
	s := newEphorGateway(t, dir)
	s.threatEngine.UpdateConfig(threat.Config{
		Enabled:     true,
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		BanDuration: threat.Duration{Duration: time.Hour},
	})

	if code := requestFrom(s, ip, "/wp-login.php"); code != http.StatusForbidden {
		t.Fatalf("la requête qui déclenche Ephor doit être refusée, reçu %d", code)
	}
	if code := requestFrom(s, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("le ban Ephor doit bloquer les requêtes suivantes sans l'Admin, reçu %d", code)
	}
	rows, err := s.bansDB.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "threat-"+ip || rows[0].Source != "threat" || rows[0].ExpiresAt == nil ||
		time.Until(*rows[0].ExpiresAt) < 50*time.Minute {
		t.Fatalf("ban Ephor persisté attendu (durée de la config), reçu %+v", rows)
	}
	if n, _ := s.bansDB.RecentBanCount(time.Now().Add(-24*time.Hour), "threat"); n != 1 {
		t.Fatalf("le ban doit être historisé pour les règles automatiques, reçu %d", n)
	}

	_ = s.bansDB.Close()
	restarted := newEphorGateway(t, dir)
	restarted.loadBansFromDisk()
	if code := requestFrom(restarted, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("le ban Ephor doit survivre à un redémarrage sans l'Admin, reçu %d", code)
	}
	if code := requestFrom(restarted, "203.0.113.61", "/"); code != http.StatusNotFound {
		t.Fatalf("une autre IP ne doit pas être bloquée, reçu %d", code)
	}
}

func TestPushedEphorConfigIsReloadedAfterRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	const scanner, routeWhitelisted, cfgWhitelisted = "203.0.113.70", "198.51.100.7", "198.51.100.8"
	route := &router.Route{ID: "app", Host: "app.example.test", EphorWhitelist: []string{routeWhitelisted}}
	s := newEphorGateway(t, dir, route)
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
	restarted := newEphorGateway(t, dir, route)
	restarted.loadThreatConfigFromDisk()
	if !restarted.threatEngine.Enabled() {
		t.Fatal("Ephor doit redémarrer actif sur sa dernière config, sans l'Admin")
	}
	if code := requestFrom(restarted, scanner, "/wp-login.php"); code != http.StatusForbidden {
		t.Fatalf("la liste personnalisée doit s'appliquer après redémarrage, reçu %d", code)
	}
	if !restarted.threatEngine.WhitelistedIP(cfgWhitelisted) || !restarted.threatEngine.WhitelistedIP(routeWhitelisted) {
		t.Fatal("listes blanches de la config et des routes attendues après redémarrage")
	}
}

func TestEphorScoreSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	const ip = "203.0.113.80"
	cfg := threat.Config{
		Enabled:     true,
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		IPScore:     threat.IPScoreConfig{Enabled: true, BanThreshold: 9, HalfLife: threat.Duration{Duration: time.Hour}},
	}
	s := newEphorGateway(t, dir)
	s.threatEngine.UpdateConfig(cfg)
	for i := 0; i < 4; i++ { // 4 × 2 points : sous le seuil de 9
		requestFrom(s, ip, "/wp-login.php")
	}
	if rows, _ := s.bansDB.ActiveBans(); len(rows) != 0 {
		t.Fatalf("ban prématuré : %+v", rows)
	}
	s.saveThreatState()
	raw, err := os.ReadFile(filepath.Join(dir, "threat-state.gpx"))
	if err != nil {
		t.Fatalf("l'état d'Ephor doit être copié sur le volume : %v", err)
	}
	if strings.Contains(string(raw), ip) {
		t.Fatal("la copie locale de l'état d'Ephor doit être chiffrée")
	}

	_ = s.bansDB.Close()
	restarted := newEphorGateway(t, dir)
	restarted.threatEngine.UpdateConfig(cfg)
	restarted.loadThreatStateFromDisk()
	requestFrom(restarted, ip, "/wp-login.php") // 5ᵉ requête : 8 points restaurés (à peine décrus) + 2 passent le seuil
	if code := requestFrom(restarted, ip, "/"); code != http.StatusForbidden {
		t.Fatalf("le score cumulé doit survivre au redémarrage et bannir l'IP, reçu %d", code)
	}
}

// Un ordre d'effacement RGPD réécrit aussitôt les copies locales : un redémarrage avant le prochain tour de sauvegarde
// (5 minutes) ne doit rien ressusciter de l'IP effacée.
func TestEraseOrderRewritesTheEphorStateBeforeTheNextAutosave(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_BEHAVIOR_STATE_PATH", filepath.Join(dir, "behavior-state.gpx"))
	const ip = "203.0.113.97"
	cfg := threat.Config{
		Enabled:     true,
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		IPScore:     threat.IPScoreConfig{Enabled: true, BanThreshold: 9, HalfLife: threat.Duration{Duration: time.Hour}},
	}
	s, _ := behaviorGateway(t, dir, cfg)
	for i := 0; i < 150; i++ {
		requestFrom(s, ip, "/ok")
	}
	for i := 0; i < 4; i++ { // 4 × 2 points : sous le seuil de 9
		requestFrom(s, ip, "/wp-login.php")
	}
	if s.behavior.TrustBonus(ip) == 0 {
		t.Fatal("précondition : 150 requêtes propres donnent de la confiance")
	}
	s.persistEphorState() // ce que ferait le tour de sauvegarde, avant l'ordre d'effacement

	s.applyEraseIPs([]edgews.EraseEntry{{IP: ip}})

	_ = s.bansDB.Close()
	restarted, _ := behaviorGateway(t, dir, cfg)
	restarted.loadThreatStateFromDisk()
	restarted.loadBehaviorStateFromDisk()
	if restarted.behavior.TrustBonus(ip) != 0 {
		t.Fatal("l'historique propre de l'IP effacée est revenu après le redémarrage")
	}
	requestFrom(restarted, ip, "/wp-login.php") // 8 points restaurés + 2 passeraient le seuil
	if code := requestFrom(restarted, ip, "/"); code == http.StatusForbidden {
		t.Fatal("le score de l'IP effacée est revenu après le redémarrage")
	}
}

func TestEphorBanExplanationIsPersistedAndSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	const ip = "203.0.113.90"
	cfg := threat.Config{
		Enabled:     true,
		CustomLists: threat.CustomListsConfig{Paths: []string{"/wp-login.php"}},
		IPScore:     threat.IPScoreConfig{Enabled: true, BanThreshold: 5, HalfLife: threat.Duration{Duration: time.Hour}},
	}
	s := newEphorGateway(t, dir)
	s.threatEngine.UpdateConfig(cfg)
	for i := 0; i < 3; i++ { // 3 × 2 points
		requestFrom(s, ip, "/wp-login.php")
	}
	rows, err := s.bansDB.ActiveBans()
	if err != nil || len(rows) != 1 {
		t.Fatalf("ban attendu : %v %+v", err, rows)
	}
	want := func(signals []router.BanSignal) {
		t.Helper()
		if len(signals) != 1 || signals[0].Name != "custom_path" || signals[0].Points != 6 || signals[0].Value != "/wp-login.php" {
			t.Fatalf("explication du ban : %+v", signals)
		}
	}
	want(rows[0].Signals)

	_ = s.bansDB.Close()
	restarted := newEphorGateway(t, dir)
	rows, err = restarted.bansDB.ActiveBans()
	if err != nil || len(rows) != 1 {
		t.Fatalf("ban relu : %v %+v", err, rows)
	}
	want(rows[0].Signals)
}

// behaviorGateway : une passerelle avec une route réelle (backend qui répond 200 sur /ok, 404 ailleurs), le magasin comportemental commun
// à Ephor et au WAF, comme au démarrage.
func behaviorGateway(t *testing.T, dir string, cfg threat.Config) (*Server, *router.Route) {
	t.Helper()
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/ok" {
			return
		}
		w.WriteHeader(http.StatusNotFound)
	}))
	t.Cleanup(backend.Close)
	route := &router.Route{ID: "app", Host: "app.example.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}},
		WAF: &router.WAFConfig{Enabled: true, Mode: "detect", BehaviorEnabled: true, BehaviorThreshold: 1000}}
	s := newEphorGateway(t, dir, route)
	s.health = proxy.NewBackendHealth(s.log.Logger())
	s.behavior = behavior.NewStore(0)
	s.wafEngine = waf.NewEngine(&router.WAFConfig{Enabled: true, Mode: "detect"}, s.log.Logger())
	s.wafEngine.SetBehaviorStore(s.behavior)
	s.threatEngine.SetBehaviorStore(s.behavior)
	s.threatEngine.UpdateConfig(cfg)
	return s, route
}

func TestEphorBansAScannerOnTheCommonNoteAndExplainsIt(t *testing.T) {
	dir := t.TempDir()
	const ip = "203.0.113.95"
	cfg := threat.Config{
		Enabled:  true,
		IPScore:  threat.IPScoreConfig{Enabled: true, BanThreshold: 6, HalfLife: threat.Duration{Duration: time.Hour}},
		Behavior: threat.BehaviorConfig{Signals: map[string]string{behavior.SignalHigh4xxRate: threat.BehaviorBlock, behavior.SignalPathScanning: threat.BehaviorBlock}},
	}
	s, _ := behaviorGateway(t, dir, cfg)
	var last int
	for i := 0; i < 40 && last != http.StatusForbidden; i++ {
		last = requestFrom(s, ip, fmt.Sprintf("/page-%d", i))
	}
	if last != http.StatusForbidden {
		t.Fatalf("un scanner qui balaie des chemins (404 sur 15 chemins distincts) doit finir banni, dernier statut %d", last)
	}
	rows, err := s.bansDB.ActiveBans()
	if err != nil || len(rows) != 1 || rows[0].Source != "threat" {
		t.Fatalf("ban attendu : %v %+v", err, rows)
	}
	names := map[string]float64{}
	for _, sg := range rows[0].Signals {
		names[sg.Name] = sg.Points
	}
	if names[behavior.SignalHigh4xxRate] != 4 || names[behavior.SignalPathScanning] != 3 {
		t.Fatalf("le ban doit s'expliquer par les signaux de comportement : %+v", rows[0].Signals)
	}

	// Une autre IP, mêmes requêtes, mais en detect : mêmes signaux, aucun ban.
	cfg.Behavior = threat.BehaviorConfig{}
	s2, _ := behaviorGateway(t, t.TempDir(), cfg)
	for i := 0; i < 40; i++ {
		if code := requestFrom(s2, ip, fmt.Sprintf("/page-%d", i)); code == http.StatusForbidden {
			t.Fatalf("des signaux en detect ne bannissent jamais (requête %d)", i)
		}
	}
	if rows, _ := s2.bansDB.ActiveBans(); len(rows) != 0 {
		t.Fatalf("aucun ban en detect : %+v", rows)
	}
	if sig := s2.behavior.Signals(ip); len(sig) == 0 {
		t.Fatal("les signaux sont tout de même calculés en detect")
	}
}

func TestBehaviorStateSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_BEHAVIOR_STATE_PATH", filepath.Join(dir, "behavior-state.gpx"))
	s, _ := behaviorGateway(t, dir, threat.Config{Enabled: true})
	for i := 0; i < 150; i++ {
		requestFrom(s, "203.0.113.96", "/ok")
	}
	if s.behavior.TrustBonus("203.0.113.96") == 0 {
		t.Fatal("150 requêtes propres doivent donner de la confiance")
	}
	s.saveBehaviorState()
	raw, err := os.ReadFile(filepath.Join(dir, "behavior-state.gpx"))
	if err != nil || strings.Contains(string(raw), "203.0.113.96") {
		t.Fatalf("la copie locale doit exister et être chiffrée : %v", err)
	}

	_ = s.bansDB.Close()
	restarted, _ := behaviorGateway(t, dir, threat.Config{Enabled: true})
	restarted.loadBehaviorStateFromDisk()
	if restarted.behavior.TrustBonus("203.0.113.96") == 0 {
		t.Fatal("l'historique propre doit survivre à un redémarrage sans l'Admin")
	}

	// L'effacement RGPD d'une IP retire aussi cet historique.
	restarted.threatEngine.ForgetIP("203.0.113.96")
	if restarted.behavior.TrustBonus("203.0.113.96") != 0 {
		t.Fatal("effacement RGPD : l'historique propre doit disparaître")
	}
}
