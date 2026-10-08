// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"path/filepath"
	"strings"

	"github.com/vincamok/goproxify/internal/modules"
)

// Parser extrait les proxies d'un contenu de configuration tierce.
type Parser func(content string) ([]DetectedProxy, error)

// formatRegistry range les formats d'import (modules de la famille « Importer », ADR 0007).
// Ajouter un format = un appel à registerFormat depuis init() : l'API, la CLI et le sélecteur de
// l'interface en découlent.
var formatRegistry = modules.NewRegistry[Parser]()

// fallbackFormat est le format appliqué à un identifiant inconnu : le JSON générique, comme avant
// l'introduction du registre.
const fallbackFormat = "json"

// Attributs d'un manifeste de format (modules.Manifest.Attrs) :
//   - hint          : courte description affichée sous le nom ;
//   - extensions    : extensions de fichier (avec le point) qui désignent ce format ;
//   - basenames     : noms de fichier exacts (sans casse), ex. « caddyfile » ;
//   - name_contains : sous-chaînes du nom de fichier, ex. « nginx » ;
//   - suffixes      : fins de nom de fichier, ex. « .gpx-admin-backup ».
//
// La détection par nom de fichier parcourt les formats dans l'ordre de déclaration ; le premier
// qui correspond l'emporte.
func registerFormat(id, label, hint string, attrs map[string]any, p Parser) {
	if attrs == nil {
		attrs = map[string]any{}
	}
	attrs["hint"] = hint
	formatRegistry.Register(modules.Manifest{Type: id, Label: label, Attrs: attrs}, p)
}

func init() {
	registerFormat("nginx", "nginx", "Blocs server { }", map[string]any{
		"extensions": []string{".conf"}, "name_contains": []string{"nginx"},
	}, parseNginx)
	registerFormat("traefik-yaml", "Traefik YAML", "http.routers + services", map[string]any{
		"extensions": []string{".yml", ".yaml"},
	}, parseTraefikYAML)
	registerFormat("traefik-toml", "Traefik TOML", "Format TOML", map[string]any{
		"extensions": []string{".toml"},
	}, parseTraefikTOML)
	registerFormat("caddy", "Caddy", "Caddyfile", map[string]any{
		"basenames": []string{"caddyfile"}, "extensions": []string{".caddy"},
	}, parseCaddy)
	registerFormat("haproxy", "HAProxy", "frontend / backend", map[string]any{
		"extensions": []string{".cfg"}, "name_contains": []string{"haproxy"},
	}, parseHAProxy)
	registerFormat("goproxify", "Goproxify JSON", "Export natif", map[string]any{
		"suffixes": []string{".gpx-admin-backup"},
	}, parseGoproxify)
	registerFormat("json", "JSON générique", "host + backends", map[string]any{
		"extensions": []string{".json"},
	}, parseGenericJSON)
}

// ParseConfig extrait les proxies d'une configuration tierce. Un format inconnu est traité comme
// du JSON générique.
func ParseConfig(format, content string) ([]DetectedProxy, error) {
	p, _, ok := formatRegistry.Lookup(format)
	if !ok {
		p, _, _ = formatRegistry.Lookup(fallbackFormat)
	}
	return p(content)
}

// Formats retourne les manifestes des formats d'import, dans l'ordre d'affichage.
func Formats() []modules.Manifest { return formatRegistry.Manifests() }

// DetectFormat devine le format d'après le nom de fichier ; JSON générique à défaut.
func DetectFormat(path string) string {
	ext := strings.ToLower(filepath.Ext(path))
	base := strings.ToLower(filepath.Base(path))
	for _, m := range formatRegistry.Manifests() {
		if formatMatches(m, ext, base) {
			return m.Type
		}
	}
	return fallbackFormat
}

func formatMatches(m modules.Manifest, ext, base string) bool {
	for _, e := range m.Strings("extensions") {
		if ext == e {
			return true
		}
	}
	for _, b := range m.Strings("basenames") {
		if base == b {
			return true
		}
	}
	for _, s := range m.Strings("name_contains") {
		if strings.Contains(base, s) {
			return true
		}
	}
	for _, s := range m.Strings("suffixes") {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}
