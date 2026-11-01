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

func securityPermissionForTest(r *http.Request) (string, bool) {
	switch {
	case strings.HasPrefix(r.URL.Path, "/api/v1/security/surface"):
		return "surface:read", true
	case r.Method == http.MethodGet:
		return "netsec:read", true
	}
	return "netsec:respond", true
}

// La sécurité réseau se borne aux passerelles et groupes du périmètre : listes filtrées, actions jugées sur la portée de
// l'objet, vues globales fermées.
func TestSecurityIsBoundedToThePerimeter(t *testing.T) {
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

	db, err := admindb.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO security_bans (id, ip, reason, source, edge_name, target_scope) VALUES
			('b-lan', '1.1.1.1', 'x', 'native', 'lan-1', ''), ('b-net', '2.2.2.2', 'x', 'native', 'net-1', ''),
			('b-glob', '3.3.3.3', 'x', 'native', '', ''), ('b-grp', '4.4.4.4', 'x', 'native', '', 'group:paris-lan')`,
		`INSERT INTO security_cves (id, backend_url, cve_id, status, edge_name) VALUES (11, 'http://a', 'CVE-1', 'open', 'lan-1'), (12, 'http://b', 'CVE-2', 'open', 'net-1')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}

	var reached string
	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = r.Method + " " + r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/security/bans":
			if r.Method == http.MethodGet {
				w.Write([]byte(`[{"id":"b-lan","edge_name":"lan-1","target_scope":""},{"id":"b-net","edge_name":"net-1","target_scope":""},` + //nolint:errcheck
					`{"id":"b-glob","edge_name":"","target_scope":""},{"id":"b-grp","edge_name":"","target_scope":"group:paris-lan"}]`))
				return
			}
		case "/api/v1/security/threats":
			w.Write([]byte(`[{"id":"t1","edge_name":"lan-1"},{"id":"t2","edge_name":"net-1"},{"id":"t3","edge_name":""}]`)) //nolint:errcheck
			return
		}
		w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
	})
	h := ScopeSecurity(db, securityPermissionForTest)(inner)

	lan := &rbac.Caller{UserID: "u", Role: "user", Accesses: []rbac.TeamAccess{{
		Levels: map[string]string{"netsec": "respond"}, Perimeter: rbac.Perimeter{Group: rbac.GroupCriterion{Name: "paris-lan"}}}}}
	open := &rbac.Caller{UserID: "o", Role: "user", Accesses: []rbac.TeamAccess{{Levels: map[string]string{"netsec": "respond"}}}}

	call := func(c *rbac.Caller, method, path, body string) (int, string) {
		reached = ""
		r := httptest.NewRequest(method, path, strings.NewReader(body))
		r = r.WithContext(rbac.WithCaller(r.Context(), c))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	ids := func(body string) string {
		var out []string
		for _, part := range strings.Split(body, `"id":"`)[1:] {
			out = append(out, part[:strings.Index(part, `"`)])
		}
		return strings.Join(out, ",")
	}

	if code, body := call(lan, "GET", "/api/v1/security/bans", ""); code != 200 || ids(body) != "b-lan,b-grp" {
		t.Errorf("bans visibles : %d %s", code, body)
	}
	if _, body := call(lan, "GET", "/api/v1/security/threats", ""); ids(body) != "t1" {
		t.Errorf("menaces visibles : %s", body)
	}
	if code, _ := call(lan, "DELETE", "/api/v1/security/bans/b-lan", ""); code != 200 {
		t.Errorf("débannir dans son périmètre : %d", code)
	}
	for _, id := range []string{"b-net", "b-glob"} {
		if code, _ := call(lan, "DELETE", "/api/v1/security/bans/"+id, ""); code != http.StatusForbidden || reached != "" {
			t.Errorf("débannir %s hors périmètre : %d (atteint : %q)", id, code, reached)
		}
	}
	if code, _ := call(lan, "POST", "/api/v1/security/bans", `{"ip":"5.5.5.5","target_scope":"group:paris-lan"}`); code != 200 {
		t.Errorf("bannir sur son groupe : %d", code)
	}
	for _, body := range []string{`{"ip":"5.5.5.5","target_scope":"net-1"}`, `{"ip":"5.5.5.5"}`} {
		if code, _ := call(lan, "POST", "/api/v1/security/bans", body); code != http.StatusForbidden {
			t.Errorf("bannir hors périmètre ou globalement (%s) : %d", body, code)
		}
	}
	if code, _ := call(lan, "PATCH", "/api/v1/security/cves/11", `{}`); code != 200 {
		t.Errorf("CVE de son groupe : %d", code)
	}
	if code, _ := call(lan, "PATCH", "/api/v1/security/cves/12", `{}`); code != http.StatusForbidden {
		t.Errorf("CVE d'un autre groupe : %d", code)
	}
	for _, p := range []string{"/api/v1/security", "/api/v1/security/overview", "/api/v1/security/bans/whitelist", "/api/v1/security/ip-trace", "/api/v1/security/bans/import", "/api/v1/security/bans/history"} {
		if code, _ := call(lan, "GET", p, ""); code != http.StatusForbidden {
			t.Errorf("%s : vue globale, %d", p, code)
		}
	}
	// La surface juge chaque proxy elle-même ; un accès sans critère voit tout.
	if code, _ := call(lan, "GET", "/api/v1/security/surface/report", ""); code != 200 {
		t.Errorf("surface : %d", code)
	}
	if _, body := call(open, "GET", "/api/v1/security/bans", ""); ids(body) != "b-lan,b-net,b-glob,b-grp" {
		t.Errorf("accès sans critère : %s", body)
	}
	if code, _ := call(open, "GET", "/api/v1/security/overview", ""); code != 200 {
		t.Errorf("vue globale pour l'accès sans critère : %d", code)
	}
}
