// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import "strings"

var protectedExact = map[string]bool{
	"/": true, "/robots.txt": true, "/favicon.ico": true, "/sitemap.xml": true, "/sitemap_index.xml": true,
	"/ads.txt": true, "/humans.txt": true, "/security.txt": true, "/manifest.json": true, "/api": true, "/api/": true,
	"/index.html": true, "/apple-touch-icon.png": true, "/apple-touch-icon-precomposed.png": true,
}

var protectedPrefix = []string{"/.well-known/", "/health", "/ready", "/live", "/status", "/ping", "/static/", "/assets/"}

// Protected dit qu'un gabarit n'est jamais proposable, quel que soit son lift : les pages que tout visiteur ou tout
// client demande. Ce n'est pas un filtre de qualité, c'est la garantie que le référentiel ne peut pas fermer le site.
func Protected(template string) bool {
	if protectedExact[template] {
		return true
	}
	for _, p := range protectedPrefix {
		if strings.HasPrefix(template, p) {
			return true
		}
	}
	return false
}

// Specific dit qu'un gabarit nomme assez précisément une cible pour être retenu : un seul segment qui est une variable,
// ou un chemin vide, couvrirait n'importe quelle ressource.
func Specific(template string) bool {
	trim := strings.Trim(template, "/")
	if trim == "" {
		return false
	}
	segs := strings.Split(trim, "/")
	for _, s := range segs {
		if !strings.HasPrefix(s, "{") {
			return true
		}
	}
	return false
}
