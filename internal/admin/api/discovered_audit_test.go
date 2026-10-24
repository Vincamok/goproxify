// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestSecurityTemplatePrefersAdminSnippets(t *testing.T) {
	route := &router.Route{Host: "app.example.fr", Backends: []router.Backend{{URL: "http://10.0.0.5:80"}}}
	missing := auditMissing(route)
	if len(missing) != 3 {
		t.Fatalf("une route nue manque de tls, waf et rate_limit, obtenu %v", missing)
	}

	fixed := applySecurityTemplate(route, missing, []snippetRef{{ID: "sn-waf", Type: "waf"}})
	if !fixed.TLSEnabled || len(fixed.SnippetIDs) != 1 || fixed.SnippetIDs[0] != "sn-waf" {
		t.Fatalf("le snippet WAF de l'Admin doit être préféré : %+v", fixed)
	}
	if fixed.WAF != nil {
		t.Fatal("pas de WAF en ligne quand un snippet le porte")
	}
	if fixed.RateLimit == nil || fixed.RateLimit.RequestsPerSecond != 100 || fixed.RateLimit.Burst != 50 {
		t.Fatalf("sans snippet, rate limit par défaut : %+v", fixed.RateLimit)
	}
	if len(route.SnippetIDs) != 0 || route.WAF != nil || route.TLSEnabled {
		t.Fatal("la route d'origine ne doit pas être modifiée")
	}
}

func TestAuditCountsSnippetsAsControls(t *testing.T) {
	store := router.NewSnippetStore()
	store.Replace([]*router.Snippet{{ID: "sn-rl", Type: router.SnippetRateLimit, Config: json.RawMessage(`{"rps":10,"burst":5}`)}})
	route := &router.Route{TLSEnabled: true, SnippetIDs: []string{"sn-rl"}}
	got := auditMissing(router.ResolveSnippets(route, store))
	if len(got) != 1 || got[0] != "waf" {
		t.Fatalf("seul le WAF manque quand un snippet pose le rate limit, obtenu %v", got)
	}
}

// fakeDiscoveryEdge répond comme une passerelle : routes découvertes et proxys en production.
func fakeDiscoveryEdge(t *testing.T, containers string, proxies []*proxystore.Envelope) *httptest.Server {
	t.Helper()
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/agent/containers", func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(containers))
	})
	mux.HandleFunc("GET /internal/v1/proxies", func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]any{"production": proxies})
	})
	srv := httptest.NewServer(mux)
	t.Cleanup(srv.Close)
	return srv
}

func discoveryHandler(t *testing.T, edges map[string]string) *DiscoveredContainersHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	i := 0
	for name, url := range edges {
		i++
		_, err := db.Exec(`INSERT INTO tokens (id, node_name, role, token, node_endpoint, revoked)
			VALUES (?, ?, 'edge', ?, ?, 0)`, "tok-"+name, name, "gpx_edge_token_"+name, url)
		if err != nil {
			t.Fatal(err)
		}
	}
	return &DiscoveredContainersHandler{DB: db}
}

const bareContainer = `[{"id":"docker-host:app.example.fr","host":"app.example.fr","backends":["http://10.0.0.5:80"],"source":"docker","agent_name":"ag",
 "proxy_config":{"host":"app.example.fr","type":"http","backends":[{"url":"http://10.0.0.5:80"}],"tls_enabled":false,"lb":"adaptive"}}]`

func TestDetailAuditsAndProposesLabels(t *testing.T) {
	edge := fakeDiscoveryEdge(t, bareContainer, nil)
	h := discoveryHandler(t, map[string]string{"edge-1": edge.URL})

	c, err := h.Find(context.Background(), "app.example.fr", "")
	if err != nil {
		t.Fatal(err)
	}
	d, err := h.Detail(context.Background(), c)
	if err != nil {
		t.Fatal(err)
	}
	if len(d.Audit.Missing) != 3 || d.Audit.Grade == "" || len(d.Audit.Checks) == 0 {
		t.Fatalf("bilan incomplet : %+v", d.Audit)
	}
	added := map[string]string{}
	for _, p := range d.Audit.Added {
		added[p.Key] = p.Value
	}
	if added["goproxify.tls"] != "true" || added["goproxify.waf"] != "block" || added["goproxify.rate_limit"] != "100/s:50" {
		t.Fatalf("labels à ajouter inattendus : %v", added)
	}
	if d.FixedLabels == nil || d.FixedLabels.Formats["compose"].Text == "" {
		t.Fatal("les labels corrigés doivent être livrés dans chaque format")
	}
	if len(d.Container.ProxyConfig) != 0 {
		t.Fatal("la config brute ne sort pas de la vue détail")
	}
}

func TestConversionConfigCarriesOrigin(t *testing.T) {
	c := &DiscoveredContainer{ID: "docker-host:app.example.fr", EdgeName: "edge-1", ProxyConfig: json.RawMessage(`{"host":"app.example.fr","backends":[{"url":"http://b:80"}]}`)}
	raw, err := c.ConversionConfig("p1", time.Now())
	if err != nil {
		t.Fatal(err)
	}
	var r router.Route
	if err := json.Unmarshal(raw, &r); err != nil {
		t.Fatal(err)
	}
	if r.ID != "p1" || r.Origin == nil || r.Origin.ID != "docker-host:app.example.fr" || r.Origin.Edge != "edge-1" {
		t.Fatalf("origine perdue : %+v", r)
	}
}

func TestOrphansIgnoreSilentEdges(t *testing.T) {
	converted := func(id, edge, originID string) *proxystore.Envelope {
		cfg, _ := json.Marshal(router.Route{ID: id, Host: id + ".example.fr", Origin: &router.RouteOrigin{ID: originID, Edge: edge}})
		return &proxystore.Envelope{ID: id, Host: id + ".example.fr", Enabled: true, Config: cfg}
	}
	manual, _ := json.Marshal(router.Route{ID: "manual", Host: "manual.example.fr"})
	proxies := []*proxystore.Envelope{
		converted("alive", "edge-1", "docker-host:app.example.fr"),
		converted("gone", "edge-1", "docker-host:old.example.fr"),
		converted("unknown", "edge-down", "docker-host:x.example.fr"),
		{ID: "manual", Host: "manual.example.fr", Enabled: true, Config: manual},
	}
	edge := fakeDiscoveryEdge(t, bareContainer, proxies)
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()
	h := discoveryHandler(t, map[string]string{"edge-1": edge.URL, "edge-down": deadURL})

	got, err := h.Orphans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].ProxyID != "gone" {
		t.Fatalf("seul « gone » est orphelin (son conteneur n'est plus annoncé par une passerelle qui répond), obtenu %+v", got)
	}
}

// Un conteneur arrêté n'a pas disparu : le proxy converti depuis lui n'est pas orphelin, et le conteneur inactif ne se
// convertit pas (il n'a pas de config de proxy).
func TestOrphansIgnoreInactiveContainers(t *testing.T) {
	cfg, _ := json.Marshal(router.Route{ID: "stopped", Host: "stopped.example.fr", Origin: &router.RouteOrigin{ID: "portainer:1:aaaaaaaaaaaa:stopped.example.fr", Edge: "edge-1"}})
	proxies := []*proxystore.Envelope{{ID: "stopped", Host: "stopped.example.fr", Enabled: true, Config: cfg}}
	inactive := `[{"id":"inactive:portainer:1:aaaaaaaaaaaa:stopped.example.fr","host":"stopped.example.fr","backends":[],"source":"portainer","agent_name":"ag","inactive":true,"state":"exited"}]`
	edge := fakeDiscoveryEdge(t, inactive, proxies)
	h := discoveryHandler(t, map[string]string{"edge-1": edge.URL})

	got, err := h.Orphans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("un conteneur arrêté ne rend pas son proxy orphelin : %+v", got)
	}
	items := h.FetchFromEdges(context.Background())
	if len(items) != 1 || !items[0].Inactive || items[0].State != "exited" {
		t.Fatalf("le conteneur inactif est listé avec son état : %+v", items)
	}
	if _, err := h.Find(context.Background(), "stopped.example.fr", ""); err != ErrContainerNotFound {
		t.Fatalf("un conteneur inactif ne se convertit pas : %v", err)
	}
}
