// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	"github.com/vincamok/goproxify/internal/edge/tunnel"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// newAutonomyGateway construit une passerelle sur le volume dir, sans Admin ; deux appels sur le
// même dir simulent un redémarrage.
func newAutonomyGateway(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_AUTO_RULES_PATH", filepath.Join(dir, "auto-rules.gpx"))
	t.Setenv("GPX_TUNNEL_CONFIG_PATH", filepath.Join(dir, "tunnel-config.gpx"))
	log := edgelog.New("error", "text", "")
	return &Server{
		cfg:           &config.EdgeConfig{},
		log:           log,
		cache:         edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
		rulesEngine:   edgere.New(log.Logger(), edgere.Deps{}),
		tunnelManager: tunnel.New(log.Logger()),
	}
}

func TestAutoRulesSurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newAutonomyGateway(t, dir)
	s.applyAutoRules([]edgere.Rule{{ID: "r1", Name: "bloque-pic", Enabled: true, CooldownSec: 60}})

	raw, err := os.ReadFile(filepath.Join(dir, "auto-rules.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("bloque-pic")) {
		t.Fatal("copie locale des règles écrite en clair")
	}

	restarted := newAutonomyGateway(t, dir)
	restarted.loadAutoRulesFromDisk()
	got := restarted.rulesEngine.Rules()
	if len(got) != 1 || got[0].ID != "r1" || got[0].CooldownSec != 60 {
		t.Fatalf("règles après redémarrage sans Admin : %+v", got)
	}
}

// L'Admin peut pousser avant que le moteur n'existe : la copie doit quand même être écrite.
func TestAutoRulesPersistedBeforeEngineExists(t *testing.T) {
	dir := t.TempDir()
	s := newAutonomyGateway(t, dir)
	s.rulesEngine = nil
	s.applyAutoRules([]edgere.Rule{{ID: "r1", Name: "tôt", Enabled: true}})

	restarted := newAutonomyGateway(t, dir)
	restarted.loadAutoRulesFromDisk()
	if got := restarted.rulesEngine.Rules(); len(got) != 1 || got[0].ID != "r1" {
		t.Fatalf("règles perdues : %+v", got)
	}
}

func TestLoadAutoRulesWithoutFile(t *testing.T) {
	s := newAutonomyGateway(t, t.TempDir())
	s.loadAutoRulesFromDisk()
	if got := s.rulesEngine.Rules(); len(got) != 0 {
		t.Fatalf("sans copie locale : %+v", got)
	}
}

func TestTunnelPeersSurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newAutonomyGateway(t, dir)
	s.applyTunnelConfig(edgews.TunnelConfigPayload{Peers: []edgews.TunnelPeer{{Name: "edge-2", Addr: "edge-2:9443"}}})

	raw, err := os.ReadFile(filepath.Join(dir, "tunnel-config.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("edge-2:9443")) {
		t.Fatal("copie locale du tunnel écrite en clair")
	}

	restarted := newAutonomyGateway(t, dir)
	restarted.loadTunnelConfigFromDisk()
	if !restarted.tunnelManager.HasPeer("edge-2") {
		t.Fatal("pair du tunnel absent après redémarrage sans Admin")
	}
}
