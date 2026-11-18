// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func routedMux() *http.ServeMux {
	mux := http.NewServeMux()
	ok := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	for _, p := range []string{"/mcp", "/mcp/", "/api/v1/users", "/internal/v1/events", "/"} {
		mux.Handle(p, ok)
	}
	return mux
}

func status(h http.Handler, path string) int {
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, path, nil))
	return rr.Code
}

// Le listener dédié ne sert que /mcp : ni l'API, ni l'appairage, ni l'UI, ni un détour par « .. ».
func TestOnlyMCPServesNothingElse(t *testing.T) {
	h := onlyMCP(routedMux())
	for _, p := range []string{"/mcp", "/mcp/", "/mcp/sse"} {
		if got := status(h, p); got != http.StatusNoContent {
			t.Errorf("%s : %d, attendu 204", p, got)
		}
	}
	for _, p := range []string{"/", "/api/v1/users", "/internal/v1/events", "/mcpx", "/mcp/../api/v1/users", "/mcp/..%2fapi/v1/users", "/x/mcp"} {
		if got := status(h, p); got != http.StatusNotFound {
			t.Errorf("%s : %d, attendu 404", p, got)
		}
	}
}

// Avec un port MCP dédié, l'administration ne sert plus /mcp (un seul point d'entrée), mais tout le reste.
func TestHideMCPKeepsAdministrationOnly(t *testing.T) {
	h := hideMCP(routedMux())
	for _, p := range []string{"/mcp", "/mcp/", "/mcp/sse"} {
		if got := status(h, p); got != http.StatusNotFound {
			t.Errorf("%s : %d, attendu 404", p, got)
		}
	}
	for _, p := range []string{"/", "/api/v1/users", "/internal/v1/events", "/mcpx"} {
		if got := status(h, p); got != http.StatusNoContent {
			t.Errorf("%s : %d, attendu 204", p, got)
		}
	}
}
