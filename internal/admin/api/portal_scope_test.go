// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Le portail se borne aux passerelles et groupes du périmètre : passerelle obligatoire, objet jugé sur sa portée en base,
// portée du corps vérifiée, modèles de pages globaux fermés.
func TestPortalIsBoundedToThePerimeter(t *testing.T) {
	store := archstore.New(t.TempDir())
	cluster := func(g string) []byte { return []byte(`{"cluster":true,"cluster_group":"` + g + `"}`) }
	for _, n := range []archstore.NodeEntry{
		{ID: "e1", Role: "edge", Name: "lan-1", Config: cluster("paris-lan"), RBACRole: "viewer", Scopes: []archstore.ScopeEntry{{ID: "s1", Type: "domain", Value: "*.corp.io"}}},
		{ID: "e2", Role: "edge", Name: "net-1", Config: cluster("internet"), RBACRole: "viewer", Scopes: []archstore.ScopeEntry{{ID: "s2", Type: "domain", Value: "*.public.io"}}},
	} {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	rbac.SetGroupSource(rbac.ArchitectureGroups{Store: store})
	rbac.SetRouteSource(func(context.Context) ([]router.Route, error) { return nil, nil })
	t.Cleanup(func() { rbac.SetGroupSource(rbac.ArchitectureGroups{}); rbac.SetRouteSource(nil) })

	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO portal_users (id, email, home_edge) VALUES ('u-lan', 'a@x.fr', 'group:paris-lan'), ('u-net', 'b@x.fr', 'group:internet')`,
		`INSERT INTO portal_destinations (id, edge_name, kind, name, host, port) VALUES ('d-lan', 'lan-1', 'ssh', 'a', 'h', 22), ('d-net', 'net-1', 'ssh', 'b', 'h', 22)`,
		`INSERT INTO portal_access_requests (id, edge_name, user_id, target_id, created_at) VALUES ('r-lan', 'lan-1', 'u', 't', 'now'), ('r-net', 'net-1', 'u', 't', 'now')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNoContent)
	})
	h := ScopePortal(db, portalPermissionForTest)(inner)

	lan := &rbac.Caller{UserID: "u", Role: "user", Accesses: []rbac.TeamAccess{{
		Levels:    map[string]string{"portal_users": "manage", "portal_catalog": "manage", "portal_requests": "decide"},
		Perimeter: rbac.Perimeter{Group: rbac.GroupCriterion{Name: "paris-lan"}}}}}
	open := &rbac.Caller{UserID: "o", Role: "user", Accesses: []rbac.TeamAccess{{Levels: map[string]string{"portal_users": "manage", "portal_catalog": "manage", "portal_templates": "manage"}}}}

	call := func(c *rbac.Caller, method, target, body string) int {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r = r.WithContext(rbac.WithCaller(r.Context(), c))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code
	}
	for _, c := range []struct {
		name, method, target, body string
		want                       int
	}{
		{"liste sur sa passerelle", "GET", "/api/v1/portal/users?edge=lan-1", "", 204},
		{"liste sur son groupe", "GET", "/api/v1/portal/destinations?edge=group:paris-lan", "", 204},
		{"liste sans passerelle", "GET", "/api/v1/portal/users", "", 403},
		{"liste d'une autre passerelle", "GET", "/api/v1/portal/users?edge=net-1", "", 403},
		{"objet de son groupe par identifiant", "PUT", "/api/v1/portal/users/u-lan", `{"status":"active"}`, 204},
		{"objet d'un autre groupe par identifiant, passerelle visible en paramètre", "PUT", "/api/v1/portal/users/u-net?edge=lan-1", `{"status":"disabled"}`, 403},
		{"destination d'une autre passerelle", "DELETE", "/api/v1/portal/destinations/d-net?edge=lan-1", "", 403},
		{"destination de sa passerelle", "DELETE", "/api/v1/portal/destinations/d-lan", "", 204},
		{"déplacer un utilisateur hors de son périmètre", "PUT", "/api/v1/portal/users/u-lan", `{"home_edge":"net-1"}`, 403},
		{"créer une destination sur une autre passerelle", "POST", "/api/v1/portal/destinations?edge=lan-1", `{"edge_name":"net-1","name":"x"}`, 403},
		{"créer une destination sur sa passerelle", "POST", "/api/v1/portal/destinations?edge=lan-1", `{"edge_name":"lan-1","name":"x"}`, 204},
		{"décider une demande de sa passerelle", "POST", "/api/v1/portal/access-requests/r-lan/approve", `{}`, 204},
		{"décider une demande d'une autre passerelle", "POST", "/api/v1/portal/access-requests/r-net/approve", `{}`, 403},
		{"politique sans passerelle", "GET", "/api/v1/portal/policy", "", 403},
		{"enregistrements d'une autre passerelle", "GET", "/api/v1/portal/recordings?edge=net-1", "", 403},
		{"modèles de pages globaux", "GET", "/api/v1/portal-page-templates", "", 403},
	} {
		if got := call(lan, c.method, c.target, c.body); got != c.want {
			t.Errorf("%s : %d, attendu %d", c.name, got, c.want)
		}
	}
	// Un objet inconnu passe : le handler répond 404, rien à protéger.
	if got := call(lan, "PUT", "/api/v1/portal/users/absent?edge=lan-1", `{}`); got != 204 {
		t.Errorf("objet inconnu : %d", got)
	}
	// Un accès sans critère voit tout le portail, y compris sans passerelle.
	for _, target := range []string{"/api/v1/portal/users", "/api/v1/portal/users/u-net", "/api/v1/portal-page-templates"} {
		if got := call(open, "GET", target, ""); got != 204 {
			t.Errorf("accès sans critère, %s : %d", target, got)
		}
	}
	if call(open, "PUT", "/api/v1/portal/users/u-net", `{"home_edge":"lan-1"}`) != 204 {
		t.Error("accès sans critère : déplacer un utilisateur")
	}
}

func portalPermissionForTest(r *http.Request) (string, bool) {
	switch {
	case strings.Contains(r.URL.Path, "/destinations"):
		return "portal_catalog:manage", true
	case strings.Contains(r.URL.Path, "/access-requests"):
		return "portal_requests:decide", true
	case strings.Contains(r.URL.Path, "/portal-page-templates"):
		return "portal_templates:manage", true
	}
	return "portal_users:manage", true
}
