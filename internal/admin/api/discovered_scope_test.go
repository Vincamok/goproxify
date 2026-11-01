// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func getAs(t *testing.T, h *DiscoveredContainersHandler, user, path string) *httptest.ResponseRecorder {
	t.Helper()
	tok, err := auth.SignJWT(user, "secret", time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodGet, path, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	auth.RequireJWT("secret")(h).ServeHTTP(rec, req)
	return rec
}

func addUser(t *testing.T, h *DiscoveredContainersHandler, id, role string, grants ...[2]string) {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, 'x', ?)`, id, id+"@x.fr", role); err != nil {
		t.Fatal(err)
	}
	for i, g := range grants {
		if _, err := h.DB.Exec(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?, ?, ?, ?, 'read')`,
			id+g[1], id, g[0], g[1]); err != nil {
			t.Fatal(i, err)
		}
	}
}

const twoContainers = `[
 {"id":"docker-host:app.example.fr","host":"app.example.fr","backends":["http://10.0.0.5:80"],"source":"docker","agent_name":"ag",
  "proxy_config":{"host":"app.example.fr","type":"http","backends":[{"url":"http://10.0.0.5:80"}]}},
 {"id":"docker-host:secret.autre.io","host":"secret.autre.io","backends":["http://10.0.0.6:80"],"source":"docker","agent_name":"ag",
  "proxy_config":{"host":"secret.autre.io","type":"http","backends":[{"url":"http://10.0.0.6:80"}]}},
 {"id":"inactive:docker-host:stop.autre.io","host":"stop.autre.io","backends":[],"source":"docker","agent_name":"ag","inactive":true,"state":"exited"}
]`

func hostsOf(t *testing.T, rec *httptest.ResponseRecorder) []string {
	t.Helper()
	if rec.Code != http.StatusOK {
		t.Fatalf("statut %d : %s", rec.Code, rec.Body)
	}
	var list []DiscoveredContainer
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil {
		t.Fatal(err)
	}
	hosts := []string{}
	for _, c := range list {
		hosts = append(hosts, c.Host)
	}
	return hosts
}

// Un utilisateur dont le périmètre est un domaine ne voit que les conteneurs de ce domaine, arrêtés compris ; un admin
// sans périmètre les voit tous ; un utilisateur sans aucun grant n'en voit aucun.
func TestListIsRestrictedToTheUserScope(t *testing.T) {
	edge := fakeDiscoveryEdge(t, twoContainers, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	addUser(t, h, "scoped", "user", [2]string{"domain", "*.example.fr"})
	addUser(t, h, "bare", "user")
	addUser(t, h, "boss", "admin")

	if got := hostsOf(t, getAs(t, h, "scoped", "/api/v1/discovered-containers")); len(got) != 1 || got[0] != "app.example.fr" {
		t.Fatalf("l'utilisateur ne voit que son domaine : %v", got)
	}
	if got := hostsOf(t, getAs(t, h, "boss", "/api/v1/discovered-containers")); len(got) != 3 {
		t.Fatalf("l'admin sans périmètre voit tout : %v", got)
	}
	if got := hostsOf(t, getAs(t, h, "bare", "/api/v1/discovered-containers")); len(got) != 0 {
		t.Fatalf("sans grant, rien n'est visible : %v", got)
	}
}

// Les routes désactivées suivent le même périmètre, y compris celles qu'aucune passerelle n'annonce plus.
func TestListScopesDisabledHostsToo(t *testing.T) {
	edge := fakeDiscoveryEdge(t, twoContainers, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	addUser(t, h, "scoped", "user", [2]string{"domain", "*.example.fr"})
	if err := saveDisabledRoutes(h.DB, []string{"absent.example.fr", "absent.autre.io"}); err != nil {
		t.Fatal(err)
	}

	got := hostsOf(t, getAs(t, h, "scoped", "/api/v1/discovered-containers"))
	if len(got) != 2 {
		t.Fatalf("app.example.fr et absent.example.fr : %v", got)
	}
	for _, host := range got {
		if host == "secret.autre.io" || host == "absent.autre.io" {
			t.Fatalf("hôte hors périmètre : %v", got)
		}
	}
}

// Le détail d'un conteneur hors périmètre répond « introuvable », comme s'il n'existait pas.
func TestDetailOutsideTheScopeIsNotFound(t *testing.T) {
	edge := fakeDiscoveryEdge(t, twoContainers, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	addUser(t, h, "scoped", "user", [2]string{"domain", "*.example.fr"})

	if rec := getAs(t, h, "scoped", "/api/v1/discovered-containers/detail?id=secret.autre.io"); rec.Code != http.StatusNotFound {
		t.Fatalf("hors périmètre : %d", rec.Code)
	}
	if rec := getAs(t, h, "scoped", "/api/v1/discovered-containers/detail?id=app.example.fr"); rec.Code != http.StatusOK {
		t.Fatalf("dans le périmètre : %d %s", rec.Code, rec.Body)
	}
}

// Les proxys orphelins hors périmètre ne sont pas listés.
func TestOrphansAreScopedToo(t *testing.T) {
	gone := func(id, host string) *proxystore.Envelope {
		cfg, _ := json.Marshal(router.Route{ID: id, Host: host, Origin: &router.RouteOrigin{ID: "docker-host:" + host, Edge: "edge-a"}})
		return &proxystore.Envelope{ID: id, Host: host, Enabled: true, Config: cfg}
	}
	edge := fakeDiscoveryEdge(t, `[]`, []*proxystore.Envelope{gone("mine", "old.example.fr"), gone("theirs", "old.autre.io")})
	h := discoveryHandler(t, map[string]string{"edge-a": edge.URL})
	addUser(t, h, "scoped", "user", [2]string{"domain", "*.example.fr"})
	addUser(t, h, "boss", "admin")

	rec := getAs(t, h, "scoped", "/api/v1/discovered-containers/orphans")
	var got []OrphanProxy
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ProxyID != "mine" {
		t.Fatalf("seul l'orphelin du domaine est visible : %+v", got)
	}
	rec = getAs(t, h, "boss", "/api/v1/discovered-containers/orphans")
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 2 {
		t.Fatalf("l'admin sans périmètre voit les deux : %v %+v", err, got)
	}
}
