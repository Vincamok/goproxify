// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
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
	r = restrictedRequest(t, "/api/v1/logs?source=edge&level=error", byLabel, map[string]string{"logs": "read"}, prodAndTest...)
	if p, ok := h.scopedParams(w, r, "logs:read"); !ok || p.Restrict == nil || sourceIsEdge(r) || p.Level != "error" || r.URL.Query().Get("level") != "error" {
		t.Fatalf("source=edge à périmètre : servie par le volume de l'Admin, filtre conservé : ok=%v edge=%v", ok, sourceIsEdge(r))
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

func TestWritesAreJudgedOnTheObjectInThePerimeter(t *testing.T) {
	db := openSQLDatesDB(t)
	if _, err := db.Exec(`INSERT INTO alert_events (id, rule_id, trigger, detail, channels, fired_at) VALUES
		(1, 'r', 'high_error_rate', '{"domain":"a.corp.io"}', '[]', CURRENT_TIMESTAMP),
		(2, 'r', 'high_error_rate', '{"domain":"b.other.io"}', '[]', CURRENT_TIMESTAMP),
		(3, 'r', 'node_offline', '{"node_name":"e1"}', '[]', CURRENT_TIMESTAMP)`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO alert_rules (id, name, scope, triggers, channels) VALUES
		('in', 'dedans', '{"domain_glob":"*.corp.io"}', '[]', '[]'),
		('out', 'dehors', '{"domain_glob":"*.other.io"}', '[]', '[]'),
		('global', 'toutes', '{}', '[]', '[]')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO domains (id, domain) VALUES ('d-in', 'app.corp.io'), ('d-out', 'app.other.io')`); err != nil {
		t.Fatal(err)
	}
	levels := map[string]string{"alerts": "rules", "certs": "manage", "domains": "manage"}
	scoped := restrictedRequest(t, "/", rbac.Perimeter{Domain: "*.corp.io"}, levels)

	if !mayManageCert(scoped, "app.corp.io") || !mayManageCert(scoped, "*.corp.io") || mayManageCert(scoped, "app.other.io") {
		t.Error("certificats gérés sous un nom du périmètre")
	}
	if !mayManageDomain(scoped, "app.corp.io") || mayManageDomain(scoped, "app.other.io") {
		t.Error("domaines gérés dans le périmètre")
	}
	if !mayManageDomainID(scoped, db, "d-in") || mayManageDomainID(scoped, db, "d-out") || !mayManageDomainID(scoped, db, "inconnu") {
		t.Error("domaine retrouvé par identifiant")
	}
	if mayDelegate(scoped, domainRequest{DelegatedToEdgeID: "e2"}) || !mayDelegate(scoped, domainRequest{}) || !mayDelegate(scoped, domainRequest{DelegationMode: "passthrough"}) {
		t.Error("la délégation est une permission à part")
	}
	if !mayAckAlertEvent(scoped, db, "1") || mayAckAlertEvent(scoped, db, "2") || mayAckAlertEvent(scoped, db, "3") {
		t.Error("acquittement : domaine visible, pas d'événement sans domaine")
	}
	if !mayWriteAlertRule(scoped, db, "", "*.corp.io", true) || !mayWriteAlertRule(scoped, db, "", "*.eu.corp.io", true) ||
		mayWriteAlertRule(scoped, db, "", "*.other.io", true) || mayWriteAlertRule(scoped, db, "", "", true) {
		t.Error("création d'une règle")
	}
	if !mayWriteAlertRule(scoped, db, "in", "*.corp.io", true) || mayWriteAlertRule(scoped, db, "out", "*.corp.io", true) ||
		mayWriteAlertRule(scoped, db, "in", "*.other.io", true) || mayWriteAlertRule(scoped, db, "global", "*.corp.io", true) {
		t.Error("remplacement : l'ancien et le nouveau domaine sont jugés")
	}
	if !mayWriteAlertRule(scoped, db, "in", "", false) || mayWriteAlertRule(scoped, db, "out", "", false) || mayWriteAlertRule(scoped, db, "global", "", false) {
		t.Error("suppression")
	}
	// Un accès sans critère, ou l'absence d'appelant, ne restreint rien.
	open := restrictedRequest(t, "/", rbac.Perimeter{}, levels)
	if !mayWriteAlertRule(open, db, "global", "", true) || !mayManageCert(open, "x.any.io") {
		t.Error("accès sans critère")
	}
	if !mayManageCert(httptest.NewRequest(http.MethodGet, "/", nil), "x.any.io") || !mayWriteAlertRule(httptest.NewRequest(http.MethodGet, "/", nil), db, "", "", true) {
		t.Error("sans appelant")
	}
	// Déléguer exige domains:delegate.
	delegator := restrictedRequest(t, "/", rbac.Perimeter{}, levels)
	delegator = delegator.WithContext(rbac.WithCaller(delegator.Context(), &rbac.Caller{UserID: "u", Role: "user",
		Accesses: []rbac.TeamAccess{{Levels: levels, Permissions: []string{"domains:delegate"}}}}))
	if !mayDelegate(delegator, domainRequest{DelegatedToEdgeID: "e2"}) {
		t.Error("domains:delegate ouvre la délégation")
	}
}

// La surface applicative se juge par proxy sous les permissions du service surface : lire, apprendre, et la case enforce.
func TestSurfaceIsJudgedPerProxyUnderItsOwnPermissions(t *testing.T) {
	prod := router.Route{ID: "1", Host: "a.corp.io", Labels: map[string]string{"env": "prod"}}
	test := router.Route{ID: "2", Host: "b.corp.io", Labels: map[string]string{"env": "test"}}
	rbac.SetRouteSource(func(context.Context) ([]router.Route, error) { return []router.Route{prod, test}, nil })
	t.Cleanup(func() { rbac.SetRouteSource(nil) })

	access := func(levels map[string]string, permissions ...string) surfaceAccess {
		return surfaceAccess{role: "user", routes: routeIndex{}, grants: []rbac.TeamAccess{{
			Levels: levels, Permissions: permissions, Perimeter: rbac.Perimeter{Labels: map[string]string{"env": "prod"}}}}}
	}
	learner := access(map[string]string{"surface": "learn"})
	reader := access(map[string]string{"surface": "read"})
	enforcer := access(map[string]string{"surface": "learn"}, "surface:enforce")

	allow := func(a surfaceAccess, r router.Route, perm string) error {
		a.routes = routeIndex{strings.ToLower(r.Host): &r, r.ID: &r}
		return a.checkPermission(r.Host, perm)
	}
	if allow(reader, prod, "surface:read") != nil || allow(reader, prod, "surface:learn") != ErrSurfaceOutOfScope {
		t.Error("lecture seule : voit le proxy, ne peut pas apprendre")
	}
	if allow(learner, prod, "surface:learn") != nil || allow(learner, prod, "surface:enforce") != ErrSurfaceOutOfScope {
		t.Error("apprentissage sans la case enforce")
	}
	if allow(enforcer, prod, "surface:enforce") != nil {
		t.Error("la case enforce")
	}
	if allow(learner, test, "surface:read") != ErrSurfaceNotFound {
		t.Error("un proxy hors périmètre est introuvable")
	}
}

// Déploiement et jetons de récupération : la case du catalogue, sur un certificat du périmètre.
func TestCertDeploymentBoxesAreJudgedOnTheCertificateName(t *testing.T) {
	r := restrictedRequest(t, "/api/v1/certs/app.corp.io/deploy-targets", rbac.Perimeter{Domain: "*.corp.io"}, nil)
	r = r.WithContext(rbac.WithCaller(r.Context(), &rbac.Caller{UserID: "u", Role: "user", Accesses: []rbac.TeamAccess{{
		Perimeter: rbac.Perimeter{Domain: "*.corp.io"}, Permissions: []string{"certs:deploy"}}}}))
	if !CertAllowed(r, "certs:deploy", "app.corp.io") || CertAllowed(r, "certs:deploy", "app.other.io") {
		t.Error("déploiement : seulement sous un nom du périmètre")
	}
	if CertAllowed(r, "certs:export_key", "app.corp.io") {
		t.Error("la case de jetons de récupération n'est pas cochée")
	}
	if !CertAllowed(httptest.NewRequest(http.MethodGet, "/", nil), "certs:deploy", "x.any.io") {
		t.Error("sans appelant, rien n'est restreint")
	}
}
