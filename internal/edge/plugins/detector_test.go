// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestManifest_DetectorNeedsARequestHook(t *testing.T) {
	m := Manifest{Name: "d", Version: "1", APIVersion: APIVersion, Hooks: []string{HookResponse}, Detector: true}
	if err := m.Normalize(); err == nil || !strings.Contains(err.Error(), "detector") {
		t.Errorf("un détecteur sans hook de requête doit être refusé : %v", err)
	}
	for _, hook := range []string{HookRequest, HookRequestBody} {
		m := Manifest{Name: "d", Version: "1", APIVersion: APIVersion, Hooks: []string{hook}, Detector: true}
		if err := m.Normalize(); err != nil {
			t.Errorf("détecteur avec %s : %v", hook, err)
		}
	}
}

// Un manifeste qui ne déclare pas detector garde le même résumé, donc la même signature.
func TestManifest_DetectorLeavesOlderDigestsUntouched(t *testing.T) {
	m := Manifest{Name: "d", Version: "1", APIVersion: APIVersion, Hooks: []string{HookRequest}}
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(m)
	if strings.Contains(string(b), "detector") {
		t.Errorf("detector sérialisé quand il est faux : %s", b)
	}
}

// Coraza est le plugin de détection livré : son manifeste doit déclarer detector et les trois champs de ban que la
// passerelle lit (plugin_guard.go), sinon la configuration d'une route les refuse comme champs inconnus.
func TestCorazaManifest_IsADetectorWithBanFields(t *testing.T) {
	raw, err := os.ReadFile(filepath.Join("..", "..", "..", "examples", "plugins", "coraza", "manifest.json"))
	if err != nil {
		t.Skipf("exemple absent : %v", err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	if !m.Detector {
		t.Error("coraza doit se déclarer detector")
	}
	cm := m.ConfigManifest()
	if err := cm.Validate(map[string]any{"rules": "SecRuleEngine On", "ban_after": float64(10), "ban_window_sec": float64(60), "ban_duration_sec": "3600"}); err != nil {
		t.Errorf("configuration de ban refusée : %v", err)
	}
	if err := cm.Validate(map[string]any{"rules": "x", "ban_apres": 1}); err == nil {
		t.Error("une clé inconnue doit rester refusée")
	}
	if err := cm.Validate(map[string]any{"rules": "x", "ban_after": "beaucoup"}); err == nil {
		t.Error("ban_after doit être un nombre")
	}
}
