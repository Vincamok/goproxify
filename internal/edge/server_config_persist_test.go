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
	"github.com/vincamok/goproxify/internal/edge/portal"
)

func newConfigGateway(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_SERVER_CONFIG_PATH", filepath.Join(dir, "server-config.gpx"))
	t.Setenv("GPX_PORTAL_TEMPLATES_PATH", filepath.Join(dir, "portal-templates.gpx"))
	log := edgelog.New("error", "text", "")
	return &Server{
		cfg:    &config.EdgeConfig{},
		log:    log,
		cache:  edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
		portal: portal.NewService(log.Logger()),
	}
}

// Les timeouts poussés survivent à un redémarrage sans Admin, et un push partiel n'efface pas
// les autres valeurs.
func TestServerConfigSurvivesRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newConfigGateway(t, dir)
	s.applyServerConfig(pushedServerConfig{ReadSeconds: 99, IdleSeconds: 200})
	s.applyServerConfig(pushedServerConfig{WriteSeconds: 77})

	raw, err := os.ReadFile(filepath.Join(dir, "server-config.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("read_seconds")) {
		t.Fatal("copie locale de la config serveur écrite en clair")
	}

	restarted := newConfigGateway(t, dir)
	restarted.loadServerConfigFromDisk()
	got := restarted.cfg.Timeouts
	if got.ReadSeconds != 99 || got.IdleSeconds != 200 || got.WriteSeconds != 77 {
		t.Fatalf("timeouts après redémarrage sans Admin : %+v", got)
	}
}

// Un timeout non poussé garde la valeur de edge.json ; edge.json lui-même n'est jamais réécrit
// (sa sérialisation JSON perdait l'identité et les ports).
func TestServerConfigKeepsBootstrapValuesAndFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "edge.json")
	orig := `{"identity":{"node_name":"edge-1","token_id":"tok-1"},"network":{"http_port":8080},"timeouts":{"read_header_seconds":10}}`
	if err := os.WriteFile(path, []byte(orig), 0o640); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.LoadEdge(path)
	if err != nil {
		t.Fatal(err)
	}
	s := newConfigGateway(t, dir)
	s.cfg = cfg
	s.applyServerConfig(pushedServerConfig{ReadSeconds: 99})

	if cfg.Timeouts.ReadHeaderSeconds != 10 {
		t.Fatalf("read_header_seconds écrasé : %d", cfg.Timeouts.ReadHeaderSeconds)
	}
	after, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != orig {
		t.Fatalf("edge.json réécrit : %s", after)
	}
}

func TestLoadServerConfigWithoutFile(t *testing.T) {
	s := newConfigGateway(t, t.TempDir())
	s.loadServerConfigFromDisk()
	if s.cfg.Timeouts.ReadSeconds != 0 {
		t.Fatalf("sans copie locale : %+v", s.cfg.Timeouts)
	}
}

func TestPortalTemplatesSurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := newConfigGateway(t, dir)
	s.applyPortalTemplates([]portal.PageTemplate{{Key: portal.PageLogin, Body: "<section>connexion-perso</section>"}})

	raw, err := os.ReadFile(filepath.Join(dir, "portal-templates.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("connexion-perso")) {
		t.Fatal("copie locale des modèles écrite en clair")
	}

	restarted := newConfigGateway(t, dir)
	restarted.loadPortalTemplatesFromDisk()
	if body := restarted.portal.PageTemplatesSnapshot()[portal.PageLogin]; body != "<section>connexion-perso</section>" {
		t.Fatalf("modèle après redémarrage sans Admin : %q", body)
	}
}
