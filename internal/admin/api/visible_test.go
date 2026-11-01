// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// restrictedRequest simule une requête que la garde a rangée pour un compte « user » dont l'accès porte les niveaux
// donnés sur le périmètre donné ; les proxys connus sont ceux de routes.
func restrictedRequest(t *testing.T, target string, perimeter rbac.Perimeter, levels map[string]string, routes ...router.Route) *http.Request {
	t.Helper()
	rbac.SetRouteSource(func(context.Context) ([]router.Route, error) { return routes, nil })
	t.Cleanup(func() { rbac.SetRouteSource(nil) })
	caller := &rbac.Caller{UserID: "u", Role: "user", Accesses: []rbac.TeamAccess{{Name: "a", Perimeter: perimeter, Levels: levels}}}
	r := httptest.NewRequest(http.MethodGet, target, nil)
	return r.WithContext(rbac.WithCaller(r.Context(), caller))
}

var prodAndTest = []router.Route{
	{ID: "1", Host: "a.corp.io", Labels: map[string]string{"env": "prod"}},
	{ID: "2", Host: "b.corp.io", Labels: map[string]string{"env": "test"}},
}

func TestLogsAreRestrictedToTheHostsOfThePerimeter(t *testing.T) {
	h := &LogsHandler{}
	byLabel := rbac.Perimeter{Labels: map[string]string{"env": "prod"}}

	w := httptest.NewRecorder()
	r := restrictedRequest(t, "/api/v1/logs", byLabel, map[string]string{"logs": "read"}, prodAndTest...)
	p, ok := h.scopedParams(w, r, "logs:read")
	if !ok || p.Restrict == nil || len(p.Restrict.Hosts) != 1 || p.Restrict.Hosts[0] != "a.corp.io" || p.Restrict.System {
		t.Fatalf("restriction : ok=%v %+v", ok, p.Restrict)
	}

	// Sans critère : tous les hôtes, mais ni les lignes sans hôte ni les logs système sans accès dédié.
	w = httptest.NewRecorder()
	r = restrictedRequest(t, "/api/v1/logs", rbac.Perimeter{}, map[string]string{"logs": "read"}, prodAndTest...)
	p, ok = h.scopedParams(w, r, "logs:read")
	if !ok || p.Restrict == nil || p.Restrict.System || len(p.Restrict.Patterns) != 1 {
		t.Fatalf("accès sans critère : ok=%v %+v", ok, p.Restrict)
	}
	if !p.Restrict.Allows(logs.Entry{Domain: "x.any.io", Status: 200}) || p.Restrict.Allows(logs.Entry{Status: 0}) {
		t.Fatal("tous les hôtes, pas les événements de processus")
	}

	// Les logs système sans critère ouvrent les lignes sans hôte.
	w = httptest.NewRecorder()
	r = restrictedRequest(t, "/api/v1/logs", rbac.Perimeter{}, map[string]string{"logs": "read", "system_logs": "read"}, prodAndTest...)
	if p, _ = h.scopedParams(w, r, "logs:read"); p.Restrict == nil || !p.Restrict.System {
		t.Fatal("system_logs:read sans critère ouvre les lignes système")
	}

	// Sans la permission : 403. La source passerelle n'est pas filtrable : refusée à un accès à périmètre.
	w = httptest.NewRecorder()
	r = restrictedRequest(t, "/api/v1/logs", byLabel, map[string]string{"certs": "read"}, prodAndTest...)
	if _, ok := h.scopedParams(w, r, "logs:read"); ok || w.Code != http.StatusForbidden {
		t.Fatalf("sans logs:read : ok=%v code=%d", ok, w.Code)
	}
	w = httptest.NewRecorder()
	r = restrictedRequest(t, "/api/v1/logs?source=edge", byLabel, map[string]string{"logs": "read"}, prodAndTest...)
	if _, ok := h.scopedParams(w, r, "logs:read"); ok || w.Code != http.StatusForbidden {
		t.Fatalf("source=edge à périmètre : ok=%v code=%d", ok, w.Code)
	}
	// Export : permission distincte.
	w = httptest.NewRecorder()
	r = restrictedRequest(t, "/api/v1/logs/export", byLabel, map[string]string{"logs": "read"}, prodAndTest...)
	if _, ok := h.scopedParams(w, r, "logs:export"); ok {
		t.Fatal("l'export exige le niveau Export")
	}
	// Sans garde (appel direct), rien n'est restreint.
	if p, ok := h.scopedParams(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/api/v1/logs", nil), "logs:read"); !ok || p.Restrict != nil {
		t.Fatal("pas de restriction sans appelant")
	}
}

func TestCertificatesAndAlertsFollowThePerimeter(t *testing.T) {
	r := restrictedRequest(t, "/api/v1/certs", rbac.Perimeter{Labels: map[string]string{"env": "prod"}}, map[string]string{"certs": "read", "alerts": "read"}, prodAndTest...)
	visible := visibleCerts(r)
	if !visible("a.corp.io") || !visible("*.corp.io") || visible("b.other.io") {
		t.Error("un certificat est visible quand son nom couvre un hôte du périmètre")
	}
	if rbac.CallerFrom(r.Context()) == nil || !visibleCerts(httptest.NewRequest(http.MethodGet, "/", nil))("n'importe.quoi") {
		t.Error("sans appelant, tout est visible")
	}

	events := []map[string]any{
		{"id": 1, "detail": map[string]any{"domain": "a.corp.io"}},
		{"id": 2, "detail": map[string]any{"domain": "b.corp.io"}},
		{"id": 3, "detail": map[string]any{"node_name": "edge-1"}},
	}
	got := visibleAlertEvents(r, events)
	if len(got) != 1 || got[0]["id"] != 1 {
		t.Errorf("événements visibles : %v", got)
	}

	byDomain := restrictedRequest(t, "/api/v1/alert-rules", rbac.Perimeter{Domain: "*.corp.io"}, map[string]string{"alerts": "read"})
	rule := visibleAlertRule(byDomain)
	if !rule(map[string]any{"domain_glob": "*.corp.io"}) || !rule(map[string]any{"domain_glob": "*.eu.corp.io"}) ||
		rule(map[string]any{"domain_glob": "*.other.io"}) || rule(map[string]any{}) {
		t.Error("une règle est visible quand son domaine est dans le périmètre ; sans domaine, elle vise toutes les passerelles")
	}

	all := restrictedRequest(t, "/api/v1/alert-events", rbac.Perimeter{}, map[string]string{"alerts": "read"})
	if len(visibleAlertEvents(all, events)) != 3 || !visibleAlertRule(all)(map[string]any{}) {
		t.Error("un accès sans critère voit tout")
	}
}

func TestAggregateViewsAreForUnrestrictedAccessesOnly(t *testing.T) {
	scoped := restrictedRequest(t, "/api/v1/metrics/summary", rbac.Perimeter{Domain: "*.corp.io"}, map[string]string{"dashboard": "read"})
	w := httptest.NewRecorder()
	if requireUnrestricted(w, scoped, "dashboard:read") || w.Code != http.StatusForbidden {
		t.Fatal("une vue globale est refusée à un accès à périmètre")
	}
	open := restrictedRequest(t, "/api/v1/metrics/summary", rbac.Perimeter{}, map[string]string{"dashboard": "read"})
	if !requireUnrestricted(httptest.NewRecorder(), open, "dashboard:read") {
		t.Fatal("un accès sans critère la voit")
	}
	if !requireUnrestricted(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, "/", nil), "dashboard:read") {
		t.Fatal("sans appelant, rien n'est restreint")
	}
}
