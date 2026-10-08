// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"strings"
)

// Sync aligne les plugins installés sur la liste complète envoyée par l'Admin : installe ou met à jour
// ceux dont l'empreinte ou le manifeste change, retire les absents. Un paquet invalide est signalé sans
// retirer la version qui fonctionne.
func (m *Manager) Sync(ctx context.Context, pkgs []Package) (installed, removed []string, errs []error) {
	want := map[string]bool{}
	for _, pkg := range pkgs {
		name := pkg.Manifest.Name
		want[name] = true
		m.mu.RLock()
		cur := m.plugins[name]
		m.mu.RUnlock()
		if cur != nil && cur.SHA256 == strings.ToLower(pkg.SHA256) && manifestEqual(cur.Manifest, pkg.Manifest) {
			continue
		}
		if err := m.Install(ctx, pkg); err != nil {
			errs = append(errs, fmt.Errorf("%s : %w", name, err))
			continue
		}
		installed = append(installed, name)
	}
	for _, info := range m.List() {
		if !want[info.Manifest.Name] {
			if err := m.Remove(ctx, info.Manifest.Name); err != nil {
				errs = append(errs, err)
				continue
			}
			removed = append(removed, info.Manifest.Name)
		}
	}
	return installed, removed, errs
}

// manifestEqual compare deux manifestes une fois les valeurs par défaut appliquées.
func manifestEqual(a, b Manifest) bool {
	if err := b.Normalize(); err != nil {
		return false
	}
	x, _ := json.Marshal(a)
	y, _ := json.Marshal(b)
	return bytes.Equal(x, y)
}
