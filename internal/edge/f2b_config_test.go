// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
)

func f2bTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_F2B_CONFIG_PATH", filepath.Join(dir, "fail2ban"))
	t.Setenv("GPX_F2B_CONFIG_FILE", "")
	return &Server{
		log:   edgelog.New("error", "text", ""),
		cache: edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
	}
}

// La clé d'API du bouncer reçue de l'Admin est écrite chiffrée, relue après un redémarrage sans l'Admin,
// et n'apparaît en clair dans aucun fichier.
func TestF2BConfigIsEncryptedAndSurvivesRestart(t *testing.T) {
	dir := t.TempDir()
	s := f2bTestServer(t, dir)
	want := edgef2b.Config{Enabled: true, WindowSec: 123, MaxErrors: 7, Whitelist: []string{"MARQUEUR-CONFIG"}}
	if err := s.saveF2BConfig(want); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); strings.Contains(string(b), "MARQUEUR-CONFIG") {
			t.Errorf("configuration en clair dans %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	restarted := f2bTestServer(t, dir)
	if got := restarted.loadF2BConfig(); !reflect.DeepEqual(got, want) {
		t.Fatalf("après redémarrage : %+v", got)
	}
}

// L'ancien fichier config.json en clair est migré puis supprimé.
func TestF2BLegacyPlainConfigIsMigrated(t *testing.T) {
	dir := t.TempDir()
	s := f2bTestServer(t, dir)
	legacy := edgef2b.Config{Enabled: true, WindowSec: 99, Whitelist: []string{"10.0.0.0/8"}}
	if err := edgef2b.SaveConfig("", legacy); err != nil {
		t.Fatal(err)
	}
	if got := s.loadF2BConfig(); !reflect.DeepEqual(got, legacy) {
		t.Fatalf("lecture = %+v", got)
	}
	if edgef2b.HasConfig("") {
		t.Error("ancien fichier en clair conservé")
	}
	if got := f2bTestServer(t, dir).loadF2BConfig(); !reflect.DeepEqual(got, legacy) {
		t.Fatalf("après migration et redémarrage : %+v", got)
	}
}

func TestF2BConfigDefaultsWhenNothingStored(t *testing.T) {
	if got := f2bTestServer(t, t.TempDir()).loadF2BConfig(); !reflect.DeepEqual(got, edgef2b.DefaultConfig()) {
		t.Fatalf("défaut = %+v", got)
	}
}
