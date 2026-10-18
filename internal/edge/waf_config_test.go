// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/waf"
)

func wafConfigTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_WAF_CONFIG_PATH", filepath.Join(dir, "waf-config.gpx"))
	return &Server{
		log:       edgelog.New("error", "text", ""),
		cache:     edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
		wafEngine: waf.NewEngine(nil, slog.Default()),
	}
}

// Le WAF coupé par l'Admin reste coupé après un redémarrage de la passerelle sans l'Admin.
func TestWAFSwitchSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s := wafConfigTestServer(t, dir)
	s.applyWAFConfig(waf.EngineConfig{Enabled: false})
	if s.wafEngine.Enabled() {
		t.Fatal("WAF toujours actif après la coupure")
	}
	restarted := wafConfigTestServer(t, dir)
	restarted.loadWAFConfigFromDisk()
	if restarted.wafEngine.Enabled() {
		t.Fatal("WAF rallumé par le redémarrage")
	}
	restarted.applyWAFConfig(waf.EngineConfig{Enabled: true})
	again := wafConfigTestServer(t, dir)
	again.loadWAFConfigFromDisk()
	if !again.wafEngine.Enabled() {
		t.Fatal("WAF resté coupé après réactivation")
	}
}

func TestWAFActiveWhenNothingStored(t *testing.T) {
	s := wafConfigTestServer(t, t.TempDir())
	s.loadWAFConfigFromDisk()
	if !s.wafEngine.Enabled() {
		t.Fatal("sans réglage enregistré, le WAF doit rester actif")
	}
}

// Une copie illisible n'éteint pas une protection.
func TestWAFActiveWhenStoredCopyUnreadable(t *testing.T) {
	dir := t.TempDir()
	s := wafConfigTestServer(t, dir)
	s.applyWAFConfig(waf.EngineConfig{Enabled: false})
	if err := os.WriteFile(filepath.Join(dir, "waf-config.gpx"), []byte("pas du chiffré"), 0o600); err != nil {
		t.Fatal(err)
	}
	broken := wafConfigTestServer(t, dir)
	broken.loadWAFConfigFromDisk()
	if !broken.wafEngine.Enabled() {
		t.Fatal("copie illisible : le WAF doit être actif")
	}
}
