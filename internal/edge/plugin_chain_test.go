// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func pluginTestServer(t *testing.T, dir string) *Server {
	t.Helper()
	t.Setenv("GPX_PLUGINS_DIR", filepath.Join(dir, "plugins"))
	s := &Server{
		log:   edgelog.New("error", "text", ""),
		table: &router.Table{},
		cache: edgecache.New(filepath.Join(dir, "edge-cache.gpx"), "cle-passerelle"),
	}
	s.health = proxy.NewBackendHealth(s.log.Logger())
	t.Cleanup(func() { s.ensurePluginManager().Close(context.Background()) })
	return s
}

func installPlugin(t *testing.T, s *Server, name string, wasm []byte, hooks []string, onError string) {
	t.Helper()
	sum := sha256.Sum256(wasm)
	err := s.ensurePluginManager().Install(context.Background(), plugins.Package{
		Manifest: plugins.Manifest{Name: name, Version: "1", APIVersion: plugins.APIVersion, Hooks: hooks, OnError: onError},
		SHA256:   hex.EncodeToString(sum[:]), Wasm: wasm,
	})
	if err != nil {
		t.Fatal(err)
	}
}

type reply struct {
	code    int
	body    string
	header  http.Header
	backend http.Header // en-têtes reçus par le backend
}

var pluginReqSeq int

func pluginRequest(t *testing.T, s *Server, refs ...router.PluginRef) reply {
	t.Helper()
	var seen http.Header
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seen = r.Header.Clone()
		w.Header().Set("Server", "backend")
		_, _ = io.WriteString(w, "contenu du backend")
	}))
	defer backend.Close()
	route := &router.Route{ID: fmt.Sprintf("%s-%d", t.Name(), nextPluginReq()), Host: "app.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}, Plugins: refs}
	req := httptest.NewRequest(http.MethodGet, "http://app.test/x", nil)
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	s.handlerForRoute(route, "").ServeHTTP(rr, req)
	return reply{code: rr.Code, body: rr.Body.String(), header: rr.Header(), backend: seen}
}

func TestPluginChain_RequestDenyModifyAndOrder(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	installPlugin(t, s, "deny", pt.Static(`{"action":"deny","status":451,"body":"refusé"}`), []string{"request"}, "")
	installPlugin(t, s, "tag", pt.Static(`{"action":"modify","set_headers":{"X-Plugin":"vu"},"remove_headers":["X-Remove"]}`), []string{"request"}, "")

	r := pluginRequest(t, s, router.PluginRef{Name: "deny"})
	if r.code != 451 || r.body != "refusé" || r.backend != nil {
		t.Errorf("deny : %d %q backend=%v", r.code, r.body, r.backend)
	}
	r = pluginRequest(t, s, router.PluginRef{Name: "tag"})
	if r.code != 200 || r.backend.Get("X-Plugin") != "vu" {
		t.Errorf("modify : %d en-tête reçu = %q", r.code, r.backend.Get("X-Plugin"))
	}
	// Dans l'ordre : le refus arrive avant le plugin suivant, et le backend n'est pas appelé.
	r = pluginRequest(t, s, router.PluginRef{Name: "deny"}, router.PluginRef{Name: "tag"})
	if r.code != 451 || r.backend != nil {
		t.Errorf("ordre : %d", r.code)
	}
}

func TestPluginChain_ResponseModifyAndDeny(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	installPlugin(t, s, "resp-tag", pt.Static(`{"action":"modify","set_headers":{"X-Resp":"ok"},"remove_headers":["Server"]}`), []string{"response"}, "")
	installPlugin(t, s, "resp-deny", pt.Static(`{"action":"deny","status":502,"body":"filtré"}`), []string{"response"}, "")

	r := pluginRequest(t, s, router.PluginRef{Name: "resp-tag"})
	if r.code != 200 || r.header.Get("X-Resp") != "ok" || r.header.Get("Server") != "" || r.body != "contenu du backend" {
		t.Errorf("modify : %d %v %q", r.code, r.header, r.body)
	}
	r = pluginRequest(t, s, router.PluginRef{Name: "resp-deny"})
	if r.code != 502 || r.body != "filtré" {
		t.Errorf("deny : %d %q (le corps du backend doit être écarté)", r.code, r.body)
	}
}

// Un plugin absent, ou en échec, ne laisse jamais la route publique sauf demande explicite.
func TestPluginChain_FailClosed(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	if r := pluginRequest(t, s, router.PluginRef{Name: "absent"}); r.code != 503 || r.backend != nil {
		t.Errorf("plugin absent : %d", r.code)
	}
	installPlugin(t, s, "crash", pt.Trap(), []string{"request"}, "")
	if r := pluginRequest(t, s, router.PluginRef{Name: "crash"}); r.code != 503 || r.backend != nil {
		t.Errorf("plugin en échec : %d", r.code)
	}
	installPlugin(t, s, "crash-ok", pt.Trap(), []string{"request"}, plugins.OnErrorAllow)
	if r := pluginRequest(t, s, router.PluginRef{Name: "crash-ok"}); r.code != 200 {
		t.Errorf("on_error allow : %d", r.code)
	}
}

// Une route sans plugin n'est pas touchée, et le serveur sans gestionnaire ne plante pas.
func TestPluginChain_NoPluginsNoManager(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	if r := pluginRequest(t, s); r.code != 200 {
		t.Errorf("sans plugin : %d", r.code)
	}
	s.pluginMgr = nil
	if r := pluginRequest(t, s, router.PluginRef{Name: "x"}); r.code != 503 {
		t.Errorf("sans gestionnaire : %d", r.code)
	}
}

// Les plugins installés survivent à un redémarrage de la passerelle, sans l'Admin.
func TestPlugins_SurviveRestartWithoutAdmin(t *testing.T) {
	dir := t.TempDir()
	s := pluginTestServer(t, dir)
	installPlugin(t, s, "deny", pt.Static(`{"action":"deny","status":451}`), []string{"request"}, "")

	restarted := pluginTestServer(t, dir)
	if r := pluginRequest(t, restarted, router.PluginRef{Name: "deny"}); r.code != 503 {
		t.Fatalf("avant rechargement : %d (le plugin ne doit pas être chargé tant que le disque n'est pas relu)", r.code)
	}
	restarted.loadPluginsFromDisk(context.Background())
	if r := pluginRequest(t, restarted, router.PluginRef{Name: "deny"}); r.code != 451 {
		t.Fatalf("après redémarrage : %d", r.code)
	}
}

// La liste poussée par l'Admin est la référence : un plugin absent est retiré, un inchangé n'est pas rechargé.
func TestPlugins_SyncFromAdminPush(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	mk := func(name string, wasm []byte) plugins.Package {
		sum := sha256.Sum256(wasm)
		return plugins.Package{Manifest: plugins.Manifest{Name: name, Version: "1", APIVersion: 1, Hooks: []string{"request"}}, SHA256: hex.EncodeToString(sum[:]), Wasm: wasm}
	}
	a, b := mk("a", pt.Static(`{}`)), mk("b", pt.Static(`{}`))
	s.applyPlugins([]plugins.Package{a, b})
	if n := len(s.pluginMgr.List()); n != 2 {
		t.Fatalf("après push : %d", n)
	}
	before, _ := s.pluginMgr.Get("a")
	s.applyPlugins([]plugins.Package{a})
	if n := len(s.pluginMgr.List()); n != 1 {
		t.Fatalf("après retrait : %d", n)
	}
	if after, _ := s.pluginMgr.Get("a"); after != before {
		t.Error("plugin inchangé rechargé")
	}
}

// Le cache de chaînes est indexé par l'identifiant de route : une route différente par requête de test.
func nextPluginReq() int {
	pluginReqSeq++
	return pluginReqSeq
}

// Le canal HTTP interne a le même effet que le message WebSocket push_plugins.
func TestPlugins_PushOverInternalHTTP(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	wasm := pt.Static(`{"action":"deny","status":451}`)
	sum := sha256.Sum256(wasm)
	pkgs := []plugins.Package{{
		Manifest: plugins.Manifest{Name: "http-push", Version: "1", APIVersion: 1, Hooks: []string{"request"}},
		SHA256:   hex.EncodeToString(sum[:]), Wasm: wasm,
	}}
	body, _ := json.Marshal(pkgs)
	rr := httptest.NewRecorder()
	s.handlePushPlugins(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/plugins", bytes.NewReader(body)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("code %d %s", rr.Code, rr.Body.String())
	}
	if r := pluginRequest(t, s, router.PluginRef{Name: "http-push"}); r.code != 451 {
		t.Errorf("plugin non actif : %d", r.code)
	}
	bad := httptest.NewRecorder()
	s.handlePushPlugins(bad, httptest.NewRequest(http.MethodPost, "/internal/v1/plugins", strings.NewReader("pas du json")))
	if bad.Code != http.StatusBadRequest {
		t.Errorf("corps invalide : %d", bad.Code)
	}
}

func packageOf(m plugins.Manifest, wasm []byte) plugins.Package {
	sum := sha256.Sum256(wasm)
	return plugins.Package{Manifest: m, SHA256: hex.EncodeToString(sum[:]), Wasm: wasm}
}

func wasmManifest(name string) plugins.Manifest {
	return plugins.Manifest{Name: name, Version: "1.0.0", APIVersion: 1, Hooks: []string{"request"}}
}
