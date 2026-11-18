// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
)

func underMCP(p string) bool { return p == "/mcp" || strings.HasPrefix(p, "/mcp/") }

// onlyMCP ne laisse passer que /mcp et /mcp/… ; le reste (UI, API, WebSocket, appairage) répond 404. Le listener MCP
// dédié est le seul à publier sur Internet : un port publié par erreur n'ouvre ni l'administration ni l'API. Un chemin
// avec « .. » est refusé : le routeur le nettoierait vers une autre route avant de répondre.
func onlyMCP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if !underMCP(r.URL.Path) || strings.Contains(r.URL.Path, "..") {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}

// hideMCP retire /mcp des listeners d'administration quand le MCP a le sien : un seul point d'entrée à filtrer et à surveiller.
func hideMCP(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if underMCP(r.URL.Path) {
			http.NotFound(w, r)
			return
		}
		next.ServeHTTP(w, r)
	})
}
