// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
)

func requestAs(t *testing.T, h *Handler, id, role string, grants ...string) *http.Request {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES (?, ?, 'x', ?)`, id, id+"@t.local", role); err != nil {
		t.Fatal(err)
	}
	for _, domain := range grants {
		if _, err := h.DB.Exec(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?, ?, 'domain', ?, 'write')`,
			id+domain, id, domain); err != nil {
			t.Fatal(err)
		}
	}
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	return r.WithContext(adminauth.WithUserID(r.Context(), id))
}

func adminRequest(t *testing.T, h *Handler) *http.Request {
	t.Helper()
	return requestAs(t, h, "root", "admin")
}

func hostsListed(t *testing.T, h *Handler, r *http.Request) map[string]bool {
	t.Helper()
	res, err := h.toolListProxies(r)
	if err != nil {
		t.Fatal(err)
	}
	hosts := map[string]bool{}
	for _, p := range res.([]map[string]any) {
		hosts[p["host"].(string)] = true
	}
	return hosts
}

func createAs(t *testing.T, h *Handler, host string) string {
	t.Helper()
	res, err := h.toolCreateProxy(adminRequest(t, h), map[string]any{"host": host, "backend": "http://10.0.0.5:3000"})
	if err != nil {
		t.Fatal(err)
	}
	return res.(map[string]any)["id"].(string)
}

// Un utilisateur limité à un domaine ne voit, par le MCP, que les proxys et les conteneurs de ce domaine.
func TestListProxiesIsRestrictedToTheUserScope(t *testing.T) {
	h := setupMCPDB(t)
	createAs(t, h, "app.example.com")
	createAs(t, h, "secret.autre.io")

	scoped := hostsListed(t, h, requestAs(t, h, "scoped", "user", "*.example.com"))
	if !scoped["app.example.com"] || !scoped["lab.example.com"] || scoped["secret.autre.io"] || len(scoped) != 2 {
		t.Fatalf("le domaine de l'utilisateur seulement (proxy et conteneur) : %v", scoped)
	}
	if all := hostsListed(t, h, adminRequest(t, h)); len(all) != 3 {
		t.Fatalf("l'admin sans périmètre voit tout : %v", all)
	}
	if none := hostsListed(t, h, requestAs(t, h, "bare", "user")); len(none) != 0 {
		t.Fatalf("sans grant, rien n'est visible : %v", none)
	}
}

// Hors périmètre, un proxy est introuvable : ni lecture, ni labels, ni modification, ni suppression.
func TestProxyToolsRefuseAProxyOutsideTheScope(t *testing.T) {
	h := setupMCPDB(t)
	foreign := createAs(t, h, "secret.autre.io")
	r := requestAs(t, h, "scoped", "user", "*.example.com")

	if _, err := h.toolGetProxy(r, foreign); err == nil || !strings.Contains(err.Error(), "introuvable") {
		t.Fatalf("get_proxy : %v", err)
	}
	if _, err := h.toolGetProxyLabels(r, foreign, ""); err == nil {
		t.Fatal("get_proxy_labels doit refuser")
	}
	if _, err := h.toolUpdateProxy(r, map[string]any{"id": foreign, "lb": "round_robin"}); err == nil {
		t.Fatal("update_proxy doit refuser")
	}
	if _, err := h.toolSetProxyEnabled(r, map[string]any{"id": foreign, "enabled": false}); err == nil {
		t.Fatal("set_proxy_enabled doit refuser")
	}
	if _, err := h.toolPurgeProxyCache(r, map[string]any{"id": foreign}); err == nil {
		t.Fatal("purge_proxy_cache doit refuser")
	}
	if _, err := h.toolDeleteProxy(r, foreign); err == nil {
		t.Fatal("delete_proxy doit refuser")
	}
	if _, err := h.toolGetProxy(adminRequest(t, h), foreign); err != nil {
		t.Fatalf("le proxy existe toujours : %v", err)
	}
}

// Créer ou déplacer un proxy hors de son domaine est refusé, dans son domaine c'est permis.
func TestCreateAndMoveAreBoundByTheWriteScope(t *testing.T) {
	h := setupMCPDB(t)
	r := requestAs(t, h, "scoped", "user", "*.example.com")

	if _, err := h.toolCreateProxy(r, map[string]any{"host": "x.autre.io", "backend": "http://10.0.0.5:3000"}); err != errProxyOutOfScope {
		t.Fatalf("hôte hors périmètre : %v", err)
	}
	created, err := h.toolCreateProxy(r, map[string]any{"host": "ok.example.com", "backend": "http://10.0.0.5:3000"})
	if err != nil {
		t.Fatal(err)
	}
	id := created.(map[string]any)["id"].(string)

	if _, err := h.toolUpdateProxy(r, map[string]any{"id": id, "host": "vole.autre.io"}); err != errProxyOutOfScope {
		t.Fatalf("déplacer vers un autre domaine : %v", err)
	}
	if _, err := h.toolUpdateProxy(r, map[string]any{"id": id, "lb": "round_robin"}); err != nil {
		t.Fatalf("modifier dans son domaine : %v", err)
	}
}

// Les conteneurs découverts hors périmètre ne se lisent ni ne se convertissent.
func TestContainerToolsRefuseARouteOutsideTheScope(t *testing.T) {
	h := setupMCPDB(t)
	r := requestAs(t, h, "scoped", "user", "*.autre.io")

	if _, err := h.toolGetDiscoveredContainer(r, map[string]any{"id": "lab.example.com"}); err == nil {
		t.Fatal("get_discovered_container doit refuser")
	}
	if _, err := h.toolConvertDiscoveredContainer(r, map[string]any{"id": "docker-host:lab.example.com"}); err == nil {
		t.Fatal("convert_discovered_container doit refuser")
	}
	if _, err := h.toolGetDiscoveredContainer(requestAs(t, h, "inside", "user", "*.example.com"), map[string]any{"id": "lab.example.com"}); err != nil {
		t.Fatalf("dans le périmètre : %v", err)
	}
}

// Les outils de surface suivent le périmètre : lecture et réécriture d'un proxy d'un autre domaine sont refusées avant tout appel de passerelle.
func TestSurfaceToolsRefuseAProxyOutsideTheScope(t *testing.T) {
	h := setupMCPDB(t)
	foreign := createAs(t, h, "secret.autre.io")
	r := requestAs(t, h, "scoped", "user", "*.example.com")

	for name, call := range map[string]func() (any, error){
		"get_proxy_surface":           func() (any, error) { return h.toolGetProxySurface(r, map[string]any{"proxy": foreign}) },
		"get_proxy_surface_proposals": func() (any, error) { return h.toolGetProxySurfaceProposals(r, map[string]any{"proxy": foreign}) },
		"get_proxy_surface_openapi":   func() (any, error) { return h.toolGetProxySurfaceOpenAPI(r, map[string]any{"proxy": foreign}) },
		"reset_proxy_surface":         func() (any, error) { return h.toolResetProxySurface(r, map[string]any{"proxy": foreign}) },
	} {
		if _, err := call(); err == nil || !strings.Contains(err.Error(), "introuvable") {
			t.Errorf("%s hors périmètre : %v", name, err)
		}
	}
}
