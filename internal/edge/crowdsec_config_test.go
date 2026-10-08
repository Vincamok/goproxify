// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
)

func crowdSecTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_CROWDSEC_PATH", filepath.Join(dir, "crowdsec"))
	t.Setenv("GPX_CROWDSEC_CONFIG_PATH", "")
	return &Server{
		log:   edgelog.New("error", "text", ""),
		cache: edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
	}
}

// La clé d'API du bouncer reçue de l'Admin est écrite chiffrée, relue après un redémarrage sans l'Admin,
// et n'apparaît en clair dans aucun fichier.
func TestCrowdSecConfigIsEncryptedAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s := crowdSecTestServer(t, dir)
	want := edgecrowdsec.Config{Enabled: true, APIURL: "http://lapi:8080", APIKey: "BOUNCER-KEY"}
	if err := s.saveCrowdSecConfig(want); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "BOUNCER-KEY") {
			t.Errorf("clé en clair dans %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted := crowdSecTestServer(t, dir)
	if got := restarted.loadCrowdSecConfig(); got != want {
		t.Fatalf("après redémarrage : %+v", got)
	}
}

// L'ancien fichier config.json en clair est migré puis supprimé.
func TestCrowdSecLegacyPlainConfigIsMigrated(t *testing.T) {
	dir := t.TempDir()
	s := crowdSecTestServer(t, dir)
	legacy := edgecrowdsec.Config{Enabled: true, APIURL: "http://old:8080", APIKey: "OLD-KEY"}
	if err := edgecrowdsec.SaveConfig("", legacy); err != nil {
		t.Fatal(err)
	}
	if got := s.loadCrowdSecConfig(); got != legacy {
		t.Fatalf("lecture = %+v", got)
	}
	if edgecrowdsec.HasConfig("") {
		t.Error("ancien fichier en clair conservé")
	}
	if got := crowdSecTestServer(t, dir).loadCrowdSecConfig(); got != legacy {
		t.Fatalf("après migration et redémarrage : %+v", got)
	}
}

func TestCrowdSecConfigDefaultsWhenNothingStored(t *testing.T) {
	if got := crowdSecTestServer(t, t.TempDir()).loadCrowdSecConfig(); got != edgecrowdsec.DefaultConfig() {
		t.Fatalf("défaut = %+v", got)
	}
}
