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
)

// newSettingsGateway construit une passerelle sur le volume dir, sans Admin ; deux appels
// sur le même dir simulent un redémarrage.
func newSettingsGateway(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_EDGE_SETTINGS_PATH", filepath.Join(dir, "edge-settings.gpx"))
	return &Server{
		cfg:       &config.EdgeConfig{},
		log:       edgelog.New("error", "text", ""),
		accessLog: edgelog.NewAccessLogger(""),
		cache:     edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
	}
}

// Une passerelle redémarrée pendant une coupure de l'Admin doit garder la protection des IP
// demandée : sinon son access log reçoit les IP complètes jusqu'au retour de l'Admin.
func TestPushedSettingsSurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	yes, no := true, false
	s := newSettingsGateway(t, dir)
	s.receivePushedSettings(pushedSettings{LogLevel: "warn", IPPseudonymize: &no})
	// Push isolé, comme PushIPAnonymize : ne doit pas effacer le reste de la copie locale.
	s.receivePushedSettings(pushedSettings{IPAnonymize: &yes})
	if anon, _ := s.accessLog.IPProtection(); !anon {
		t.Fatal("anonymisation non appliquée à réception")
	}

	raw, err := os.ReadFile(filepath.Join(dir, "edge-settings.gpx"))
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, []byte("ip_anonymize")) {
		t.Fatal("copie locale des réglages écrite en clair")
	}

	restarted := newSettingsGateway(t, dir)
	if anon, _ := restarted.accessLog.IPProtection(); anon {
		t.Fatal("état initial inattendu")
	}
	restarted.loadPushedSettingsFromDisk()
	if anon, pseudo := restarted.accessLog.IPProtection(); !anon || pseudo {
		t.Fatalf("après redémarrage sans Admin : anonymize=%v pseudonymize=%v, attendu true/false", anon, pseudo)
	}
	if restarted.pushed.LogLevel != "warn" {
		t.Fatalf("log_level perdu par le push isolé : %q", restarted.pushed.LogLevel)
	}
}

func TestLoadPushedSettingsWithoutFile(t *testing.T) {
	s := newSettingsGateway(t, t.TempDir())
	s.loadPushedSettingsFromDisk()
	if anon, pseudo := s.accessLog.IPProtection(); anon || pseudo {
		t.Fatalf("sans copie locale : anonymize=%v pseudonymize=%v", anon, pseudo)
	}
}
