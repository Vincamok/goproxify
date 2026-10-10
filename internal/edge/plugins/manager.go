// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
)

// Package est l'unité installée : manifeste, module et empreinte attendue. Elle est stockée chiffrée sur
// la passerelle (ADR 0008) : un plugin installé reste actif Admin coupé, y compris après un redémarrage.
type Package struct {
	Manifest Manifest `json:"manifest"`
	SHA256   string   `json:"sha256"`
	Wasm     []byte   `json:"wasm"`
}

// Manager tient les plugins chargés d'une passerelle et leur stockage chiffré.
type Manager struct {
	dir   string
	cache *edgecache.Store
	log   *slog.Logger

	mu      sync.RWMutex
	plugins map[string]*Plugin
}

// NewManager crée un gestionnaire dont les paquets sont stockés, chiffrés avec cache, dans dir.
func NewManager(cache *edgecache.Store, dir string, log *slog.Logger) *Manager {
	if log == nil {
		log = slog.Default()
	}
	return &Manager{dir: dir, cache: cache, log: log, plugins: map[string]*Plugin{}}
}

func (m *Manager) path(name string) string { return filepath.Join(m.dir, name+".gpx") }

// Install valide, charge et stocke un paquet, puis remplace l'éventuelle version précédente. L'empreinte
// du paquet est obligatoire : elle est vérifiée sur le .wasm reçu.
func (m *Manager) Install(ctx context.Context, pkg Package) error {
	if strings.TrimSpace(pkg.SHA256) == "" {
		return errors.New("empreinte sha256 requise")
	}
	p, err := Load(ctx, pkg.Manifest, pkg.Wasm, pkg.SHA256, m.log)
	if err != nil {
		return err
	}
	pkg.Manifest = p.Manifest // valeurs par défaut appliquées
	pkg.SHA256 = p.SHA256
	if err := m.cache.SaveFile(m.path(pkg.Manifest.Name), pkg); err != nil {
		p.Close(ctx)
		return fmt.Errorf("stockage chiffré : %w", err)
	}
	m.mu.Lock()
	old := m.plugins[p.Manifest.Name]
	m.plugins[p.Manifest.Name] = p
	m.mu.Unlock()
	if old != nil {
		old.Close(ctx)
	}
	return nil
}

// Remove décharge un plugin et supprime son paquet.
func (m *Manager) Remove(ctx context.Context, name string) error {
	if !nameRe.MatchString(name) {
		return fmt.Errorf("nom %q invalide", name)
	}
	m.mu.Lock()
	old := m.plugins[name]
	delete(m.plugins, name)
	m.mu.Unlock()
	if old != nil {
		old.Close(ctx)
	}
	if err := os.Remove(m.path(name)); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

// LoadAll recharge les paquets stockés (démarrage de la passerelle, sans l'Admin). Un paquet illisible
// ou invalide est ignoré et signalé ; il n'empêche pas les autres de se charger.
func (m *Manager) LoadAll(ctx context.Context) (loaded int, errs []error) {
	entries, err := os.ReadDir(m.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return 0, nil
		}
		return 0, []error{err}
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".gpx") {
			continue
		}
		var pkg Package
		ok, err := m.cache.LoadFile(filepath.Join(m.dir, e.Name()), &pkg)
		if err != nil || !ok {
			errs = append(errs, fmt.Errorf("%s : %w", e.Name(), errOr(err, "paquet absent")))
			continue
		}
		p, err := Load(ctx, pkg.Manifest, pkg.Wasm, pkg.SHA256, m.log)
		if err != nil {
			errs = append(errs, fmt.Errorf("%s : %w", e.Name(), err))
			continue
		}
		m.mu.Lock()
		if old := m.plugins[p.Manifest.Name]; old != nil {
			old.Close(ctx)
		}
		m.plugins[p.Manifest.Name] = p
		m.mu.Unlock()
		loaded++
	}
	return loaded, errs
}

func errOr(err error, msg string) error {
	if err != nil {
		return err
	}
	return errors.New(msg)
}

// Get retourne un plugin chargé.
func (m *Manager) Get(name string) (*Plugin, bool) {
	if m == nil {
		return nil, false
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	p, ok := m.plugins[name]
	return p, ok
}

// Info résume un plugin installé.
type Info struct {
	Manifest Manifest `json:"manifest"`
	SHA256   string   `json:"sha256"`
}

// List retourne les plugins chargés, triés par nom.
func (m *Manager) List() []Info {
	if m == nil {
		return nil
	}
	m.mu.RLock()
	defer m.mu.RUnlock()
	out := make([]Info, 0, len(m.plugins))
	for _, p := range m.plugins {
		out = append(out, Info{Manifest: p.Manifest, SHA256: p.SHA256})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Manifest.Name < out[j].Manifest.Name })
	return out
}

// Close décharge tous les plugins.
func (m *Manager) Close(ctx context.Context) {
	m.mu.Lock()
	defer m.mu.Unlock()
	for n, p := range m.plugins {
		p.Close(ctx)
		delete(m.plugins, n)
	}
}
