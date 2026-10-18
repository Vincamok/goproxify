// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/proxypipeline"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

func newImplicitGateway(t *testing.T) *Server {
	t.Helper()
	s := newEphorGateway(t, t.TempDir())
	s.certStore = edgetls.NewCertStore()
	s.snippetStore = router.NewSnippetStore()
	s.providerStore = router.NewAuthProviderStore()
	s.proxyStore = proxystore.New(t.TempDir())
	s.proxyPipe = proxypipeline.New(s.proxyStore)
	if err := s.proxyStore.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	return s
}

func delegationRoute() *router.Route {
	return &router.Route{
		ID: "deleg-d1", Host: "d.example.test", Type: router.RouteHTTP, TLSEnabled: true,
		Backends: []router.Backend{{URL: "https://b.example.test"}},
	}
}

func writeOverlay(t *testing.T, s *Server, rt router.Route, enabled bool) {
	t.Helper()
	cfg, _ := json.Marshal(rt)
	env := &proxystore.Envelope{ID: rt.ID, Host: rt.Host, Enabled: enabled, Config: cfg}
	if err := s.proxyStore.WriteProd(env); err != nil {
		t.Fatal(err)
	}
	if err := s.ApplyFileProxy(env); err != nil {
		t.Fatal(err)
	}
}

func TestImplicitOverlayKeepsGeneratedFieldsAndAppliesTheRest(t *testing.T) {
	s := newImplicitGateway(t)
	s.applyDelegationRoutes([]*router.Route{delegationRoute()})

	writeOverlay(t, s, router.Route{
		ID: "deleg-d1", Host: "autre.example.test", Type: router.RouteHTTP,
		Backends:  []router.Backend{{URL: "http://pirate.example.test"}},
		RateLimit: &router.RateLimitConfig{RequestsPerSecond: 5, Burst: 10},
		Static:    &router.StaticConfig{Enabled: true, Root: "/tmp"},
	}, true)

	got, ok := s.table.ByID("deleg-d1")
	if !ok {
		t.Fatal("la route implicite doit rester dans la table")
	}
	if got.Host != "d.example.test" || got.Backends[0].URL != "https://b.example.test" || !got.TLSEnabled {
		t.Fatalf("hôte, backend et TLS restent générés, obtenu %+v", got)
	}
	if got.RateLimit == nil || got.RateLimit.RequestsPerSecond != 5 {
		t.Fatal("la limite de débit de la surcouche doit s'appliquer")
	}
	if got.Static != nil {
		t.Fatal("une surcouche ne détourne pas le trafic vers un dossier statique")
	}

	s.applyDelegationRoutes([]*router.Route{delegationRoute()})
	got, _ = s.table.ByID("deleg-d1")
	if got.RateLimit == nil {
		t.Fatal("la surcouche doit survivre à un nouveau push de délégations")
	}
}

func TestImplicitOverlayDisableAndReset(t *testing.T) {
	s := newImplicitGateway(t)
	s.applyDelegationRoutes([]*router.Route{delegationRoute()})
	over := *delegationRoute()
	over.RateLimit = &router.RateLimitConfig{RequestsPerSecond: 1, Burst: 1}

	writeOverlay(t, s, over, false)
	if _, ok := s.table.ByID("deleg-d1"); ok {
		t.Fatal("une surcouche désactivée retire la route")
	}
	writeOverlay(t, s, over, true)
	if got, ok := s.table.ByID("deleg-d1"); !ok || got.RateLimit == nil {
		t.Fatal("réactiver la surcouche rétablit la route et ses réglages")
	}

	req := httptest.NewRequest(http.MethodDelete, "/internal/v1/proxies/deleg-d1", nil)
	req.SetPathValue("id", "deleg-d1")
	rec := httptest.NewRecorder()
	s.handleDeleteFileProxy(rec, req)
	got, ok := s.table.ByID("deleg-d1")
	if !ok || got.RateLimit != nil || got.Host != "d.example.test" {
		t.Fatalf("supprimer la surcouche rend la route générée intacte, obtenu %+v", got)
	}
}

func TestImplicitOverlayIsPreservedAcrossRoutePush(t *testing.T) {
	s := newImplicitGateway(t)
	s.applyDelegationRoutes([]*router.Route{delegationRoute()})
	over := *delegationRoute()
	over.RateLimit = &router.RateLimitConfig{RequestsPerSecond: 2, Burst: 2}
	writeOverlay(t, s, over, true)

	routes := s.mergePushPreservingFileProxies(nil)
	if err := s.table.Replace(routes); err != nil {
		t.Fatal(err)
	}
	count := 0
	for _, rt := range s.table.All() {
		if rt.ID == "deleg-d1" {
			count++
			if rt.RateLimit == nil || rt.Host != "d.example.test" {
				t.Fatalf("la route implicite doit garder surcouche et champs générés, obtenu %+v", rt)
			}
		}
	}
	if count != 1 {
		t.Fatalf("une seule route implicite attendue, obtenu %d", count)
	}
}

func TestImplicitRoutesAreListedAndReadable(t *testing.T) {
	s := newImplicitGateway(t)
	pass := &router.Route{ID: "deleg-p", Host: "p.example.test", TLSEnabled: true, TLSPassthrough: true, Backends: []router.Backend{{URL: "b.example.test:443"}}}
	s.applyDelegationRoutes([]*router.Route{delegationRoute(), pass})
	s.table.Upsert(&router.Route{ID: "manuel", Host: "m.example.test", Type: router.RouteHTTP})

	rec := httptest.NewRecorder()
	s.handleListFileProxies(rec, httptest.NewRequest(http.MethodGet, "/internal/v1/proxies", nil))
	var out struct {
		Production []proxystore.Envelope `json:"production"`
	}
	if err := json.NewDecoder(rec.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if len(out.Production) != 1 || out.Production[0].ID != "deleg-d1" || !out.Production[0].Implicit {
		t.Fatalf("seule la délégation terminée est listée comme implicite, obtenu %+v", out.Production)
	}

	req := httptest.NewRequest(http.MethodGet, "/internal/v1/proxies/deleg-d1", nil)
	req.SetPathValue("id", "deleg-d1")
	rec = httptest.NewRecorder()
	s.handleGetFileProxy(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("lecture d'une route implicite sans surcouche : %d", rec.Code)
	}
}

func TestPortalRouteTakesItsOverlay(t *testing.T) {
	s := newImplicitGateway(t)
	s.portal = newPortalGateway(t, t.TempDir()).portal
	over := router.Route{ID: portalPublicRouteID, Host: "access.example.test", Type: router.RouteHTTP,
		RateLimit: &router.RateLimitConfig{RequestsPerSecond: 3, Burst: 3}}
	cfg, _ := json.Marshal(over)
	if err := s.proxyStore.WriteProd(&proxystore.Envelope{ID: over.ID, Host: over.Host, Enabled: true, Config: cfg}); err != nil {
		t.Fatal(err)
	}
	s.upsertImplicitRoute(&router.Route{
		ID: portalPublicRouteID, Host: "access.example.test", Type: router.RouteHTTP, TLSEnabled: true,
		Backends: []router.Backend{{URL: "http://127.0.0.1:9", Weight: 1}},
	})
	got, ok := s.table.ByHost("access.example.test")
	if !ok || got.RateLimit == nil || got.Backends[0].URL != "http://127.0.0.1:9" {
		t.Fatalf("la route du portail doit porter sa surcouche et son backend généré, obtenu %+v", got)
	}
}
