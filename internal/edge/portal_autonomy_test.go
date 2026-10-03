// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/portal"
)

func freePort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func newPortalGateway(t *testing.T, dir string) *Server {
	t.Helper()
	s := newSentinelGateway(t, dir)
	s.portal = portal.NewService(s.log.Logger())
	t.Cleanup(s.portal.Stop)
	return s
}

func TestPushedPortalConfigIsReloadedAfterRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	t.Setenv("GPX_PORTAL_CONFIG_PATH", filepath.Join(dir, "portal-config.gpx"))
	t.Setenv("GPX_PORTAL_MASTER_KEY", "cle-maitre-test")
	payload := portalPushPayload{
		Enabled: true, PublicHost: "access.example.test", Theme: "ocean",
		SSHPort: freePort(t), HTTPPort: freePort(t), DBPath: filepath.Join(dir, "portal.gpx"),
		Views: []portal.View{{Slug: "prestataire", Theme: "foret"}, {Host: "presta.example.test", Title: "Prestataires"}},
	}
	s := newPortalGateway(t, dir)
	s.applyPortalPush(payload)
	raw, err := os.ReadFile(filepath.Join(dir, "portal-config.gpx"))
	if err != nil {
		t.Fatalf("la config poussée doit être copiée sur le volume : %v", err)
	}
	if strings.Contains(string(raw), "prestataire") {
		t.Fatal("la copie locale doit être chiffrée")
	}
	if _, ok := s.table.ByHost("presta.example.test"); !ok {
		t.Fatal("l'hôte dédié d'une vue doit être routé")
	}
	s.portal.Stop()

	restarted := newPortalGateway(t, dir)
	restarted.loadPortalConfigFromDisk()
	cfg := restarted.portal.Config()
	if !cfg.Enabled || cfg.Theme != "ocean" || len(cfg.Views) != 2 {
		t.Fatalf("le portail doit redémarrer sur sa dernière config sans l'Admin : %+v", cfg)
	}
	for _, host := range []string{"access.example.test", "presta.example.test"} {
		if _, ok := restarted.table.ByHost(host); !ok {
			t.Fatalf("route %s absente après redémarrage", host)
		}
	}

	// Une vue retirée par l'Admin retire sa route.
	payload.Views = payload.Views[:1]
	restarted.applyPortalPush(payload)
	if r, ok := restarted.table.ByHost("presta.example.test"); ok {
		t.Fatalf("la route de la vue supprimée doit disparaître : %+v", r.ID)
	}
}
