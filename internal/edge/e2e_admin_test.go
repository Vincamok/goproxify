// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgews"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
	edgews2 "github.com/vincamok/goproxify/internal/edge/ws"
)

// Bout en bout Admin → passerelle, sans simulacre du transport : l'API Admin (handlers réels, base SQLite), le
// gestionnaire WebSocket de l'Admin, un vrai WebSocket vers le hub de la passerelle, et l'API interne de la
// passerelle (révision, dry-run, promotion) appelée en HTTP par l'Admin. Les messages de configuration autres
// que les plugins sont écartés par un filtre : la passerelle de test n'initialise pas tous ses magasins.

type e2eEnv struct {
	gw      *Server
	db      *sql.DB
	admin   http.Handler
	jwt     string
	backend *httptest.Server
	routeIn chan struct{}
}

func newE2E(t *testing.T) *e2eEnv {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("GPX_DATA_PATH", filepath.Join(dir, "gw"))
	gw := pluginTestServer(t, dir)
	gw.initProxyStore()
	gw.ensurePluginManager() // créé avant que les messages WebSocket n'arrivent
	// Magasins lus par la sauvegarde du cache, déclenchée par chaque route appliquée.
	gw.certStore = edgetls.NewCertStore()
	gw.snippetStore = router.NewSnippetStore()
	gw.providerStore = router.NewAuthProviderStore()
	gw.profileStore = router.NewIPProfileStore()
	gw.banStore = router.NewBanStore()
	gw.ech = edgetls.NewECHManager()

	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { _, _ = io.WriteString(w, "backend") }))
	t.Cleanup(backend.Close)

	// Passerelle : hub WebSocket (messages de plugins seulement) + API interne des proxies.
	quiet := slog.New(slog.NewTextHandler(io.Discard, nil))
	hub := edgews2.NewHub("e2e-hmac", quiet)
	hub.SetAdminMessageHandler(func(connID string, msg edgews2.Message) error {
		if msg.Type == edgews2.TypePushPlugins {
			return gw.handleWSAdminMessage(connID, msg)
		}
		return nil
	})
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/admin", hub.ServeAdmin)
	mux.HandleFunc("POST /internal/v1/proxies/revisions", gw.handleCreateProxyRevision)
	mux.HandleFunc("GET /internal/v1/proxies/{id}", gw.handleGetFileProxy)
	mux.HandleFunc("DELETE /internal/v1/proxies/{id}", gw.handleDeleteFileProxy)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", gw.handleDryRunProxyRevision)
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", gw.handlePromoteProxyRevision)
	gwSrv := httptest.NewServer(mux)
	t.Cleanup(gwSrv.Close)

	// Admin : base, utilisateur superadmin, passerelle enregistrée, gestionnaire WebSocket.
	db, err := admindb.Open(filepath.Join(dir, "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1', 'root@test', 'x', 'superadmin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES ('11111111-1111-1111-1111-111111111111', 'tok', 'edge', 'gw1', ?)`, gwSrv.URL); err != nil {
		t.Fatal(err)
	}
	manager := edgews.NewManager("e2e-hmac", db, quiet)
	manager.Register("11111111-1111-1111-1111-111111111111", "gw1", gwSrv.URL, "admin")
	t.Cleanup(manager.Close)

	proxies := &api.ProxiesHandler{DB: db, Log: quiet}
	plug := &api.PluginsHandler{DB: db, Log: quiet, Pusher: manager}
	amux := http.NewServeMux()
	amux.Handle("/api/v1/proxies", proxies)
	amux.Handle("/api/v1/proxies/", proxies)
	amux.Handle("/api/v1/plugins", plug)
	amux.Handle("/api/v1/plugins/", plug)
	jwt, err := auth.SignJWT("u1", "e2e-secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	return &e2eEnv{gw: gw, db: db, admin: auth.RequireJWT("e2e-secret")(amux), jwt: jwt, backend: backend}
}

func (e *e2eEnv) do(method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	req := httptest.NewRequest(method, path, &buf)
	req.Header.Set("Authorization", "Bearer "+e.jwt)
	rec := httptest.NewRecorder()
	e.admin.ServeHTTP(rec, req)
	return rec
}

func (e *e2eEnv) waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(8 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// get envoie une requête à la route de la passerelle pour ce host, depuis clientIP.
func (e *e2eEnv) get(host, clientIP string) int {
	rt, ok := e.gw.table.ByHost(host)
	if !ok {
		return 0
	}
	req := httptest.NewRequest(http.MethodGet, "http://"+host+"/", nil)
	req.RemoteAddr = clientIP + ":4000"
	rec := httptest.NewRecorder()
	e.gw.handlerForRoute(rt, "").ServeHTTP(rec, req)
	return rec.Code
}

func (e *e2eEnv) proxyBody(host string, extra map[string]any) map[string]any {
	cfg := map[string]any{"host": host, "type": "http", "backends": []map[string]any{{"url": e.backend.URL}}}
	for k, v := range extra {
		cfg[k] = v
	}
	return map[string]any{"config": cfg}
}

func installDenier(t *testing.T, e *e2eEnv, name string) {
	t.Helper()
	wasm := pt.Static(`{"action":"deny","status":451,"body":"refusé par le plugin"}`)
	body := pluginBodyFor(name, wasm)
	if rec := e.do(http.MethodPost, "/api/v1/plugins", body); rec.Code != http.StatusCreated {
		t.Fatalf("installation du plugin : %d %s", rec.Code, rec.Body.String())
	}
}

func pluginBodyFor(name string, wasm []byte) map[string]any {
	p := packageOf(wasmManifest(name), wasm)
	return map[string]any{"manifest": p.Manifest, "sha256": p.SHA256, "wasm": wasm}
}

// Installer un plugin depuis l'API Admin l'active sur la passerelle par WebSocket ; une route Admin qui le
// référence est validée par la passerelle, appliquée, et le plugin s'exécute ; supprimer le plugin fait
// refuser la route (503) au lieu de la laisser publique.
func TestE2E_PluginLifecycleFromAdminToGateway(t *testing.T) {
	e := newE2E(t)
	installDenier(t, e, "denier")
	e.waitFor(t, "le plugin n'est pas arrivé sur la passerelle", func() bool { _, ok := e.gw.pluginMgr.Get("denier"); return ok })

	rec := e.do(http.MethodPost, "/api/v1/proxies", e.proxyBody("e2e.test", map[string]any{"plugins": []map[string]any{{"name": "denier"}}}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("création de la route : %d %s", rec.Code, rec.Body.String())
	}
	if code := e.get("e2e.test", "203.0.113.9"); code != 451 {
		t.Fatalf("la route doit appliquer le plugin : %d", code)
	}

	if rec := e.do(http.MethodDelete, "/api/v1/plugins/denier", nil); rec.Code != http.StatusNoContent {
		t.Fatalf("suppression : %d %s", rec.Code, rec.Body.String())
	}
	e.waitFor(t, "le plugin n'a pas été retiré de la passerelle", func() bool { _, ok := e.gw.pluginMgr.Get("denier"); return !ok })
	if code := e.get("e2e.test", "203.0.113.9"); code != 503 {
		t.Errorf("plugin supprimé : %d (attendu 503, jamais 200)", code)
	}
}

// Les validations ajoutées (détecteurs, plugins) s'exécutent sur la passerelle quand l'Admin publie une route : une
// configuration invalide est refusée avec le motif, rien n'est appliqué ; une configuration valide s'applique.
func TestE2E_RouteValidationHappensOnTheGateway(t *testing.T) {
	e := newE2E(t)
	for name, extra := range map[string]map[string]any{
		"mode du filtre IP": {"ip_filter": map[string]any{"mode": "blok", "cidrs": []string{"10.0.0.0/8"}}},
		"CIDR invalide":     {"ip_filter": map[string]any{"mode": "deny", "cidrs": []string{"10.0.0.0/40"}}},
		"pays invalide":     {"geo_ip": map[string]any{"mode": "deny", "countries": []string{"CHINE"}}},
		"regex WAF":         {"waf": map[string]any{"enabled": true, "custom_rules": []map[string]any{{"pattern": "("}}}},
		"plugin inconnu":    {"plugins": []map[string]any{{"name": "n-existe-pas"}}},
		"plugin en double":  {"plugins": []map[string]any{{"name": "x"}, {"name": "x"}}},
	} {
		host := strings.ReplaceAll(strings.ToLower(name), " ", "-") + ".test"
		rec := e.do(http.MethodPost, "/api/v1/proxies", e.proxyBody(host, extra))
		if rec.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s : %d (attendu 422) %s", name, rec.Code, rec.Body.String())
			continue
		}
		if !strings.Contains(rec.Body.String(), "errors") {
			t.Errorf("%s : le motif du refus manque : %s", name, rec.Body.String())
		}
		if _, ok := e.gw.table.ByHost(host); ok {
			t.Errorf("%s : route appliquée malgré le refus", name)
		}
	}

	// Un filtre IP valide, créé par l'Admin, est appliqué par la passerelle.
	rec := e.do(http.MethodPost, "/api/v1/proxies", e.proxyBody("filtre.test", map[string]any{"ip_filter": map[string]any{"mode": "deny", "cidrs": []string{"203.0.113.0/24"}}}))
	if rec.Code != http.StatusCreated {
		t.Fatalf("route valide : %d %s", rec.Code, rec.Body.String())
	}
	if code := e.get("filtre.test", "203.0.113.9"); code != http.StatusForbidden {
		t.Errorf("IP interdite : %d", code)
	}
	if code := e.get("filtre.test", "198.51.100.7"); code != http.StatusOK {
		t.Errorf("IP autorisée : %d", code)
	}
}
