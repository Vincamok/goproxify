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

	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// La topologie se borne aux groupes que l'appelant voit : ceux qui servent ses proxys, ceux que son accès à
// l'infrastructure désigne ; un Agent suit sa passerelle.
func TestTopologyIsBoundedToTheVisibleGroups(t *testing.T) {
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
	if err := store.SetGroupAttributes("internet", archstore.GroupAttributes{Environment: "prod"}); err != nil {
		t.Fatal(err)
	}
	rbac.SetGroupSource(rbac.ArchitectureGroups{Store: store})
	rbac.SetRouteSource(func(context.Context) ([]router.Route, error) {
		return []router.Route{{ID: "1", Host: "a.corp.io", Labels: map[string]string{"env": "prod"}}, {ID: "2", Host: "x.public.io", Labels: map[string]string{"env": "test"}}}, nil
	})
	t.Cleanup(func() { rbac.SetGroupSource(rbac.ArchitectureGroups{}); rbac.SetRouteSource(nil) })

	db, err := admindb.Open(filepath.Join(t.TempDir(), "n.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO nodes (id, node_name, role) VALUES ('e1','lan-1','edge'), ('e2','net-1','edge')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}

	inner := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/api/v1/nodes":
			w.Write([]byte(`[{"id":"e1","node_name":"lan-1","role":"edge"},{"id":"e2","node_name":"net-1","role":"edge"},` + //nolint:errcheck
				`{"id":"a1","node_name":"agent-lan","role":"agent","target_edge":"lan-1"},{"id":"a2","node_name":"agent-net","role":"agent","target_edge":"net-1"},{"id":"a3","node_name":"orphan","role":"agent"}]`))
		case "/api/v1/node-events":
			w.Write([]byte(`[{"node_name":"lan-1"},{"node_name":"net-1"}]`)) //nolint:errcheck
		case "/api/v1/architecture/groups":
			w.Write([]byte(`{"paris-lan":[{"id":"e1"}],"internet":[{"id":"e2"}]}`)) //nolint:errcheck
		default:
			w.Write([]byte(`{"ok":true}`)) //nolint:errcheck
		}
	})
	h := ScopeTopology(db)(inner)

	call := func(c *rbac.Caller, path string) (int, string) {
		r := httptest.NewRequest(http.MethodGet, path, nil)
		r = r.WithContext(rbac.WithCaller(r.Context(), c))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, r)
		return rec.Code, rec.Body.String()
	}
	names := func(body string) []string {
		var rows []map[string]any
		_ = json.Unmarshal([]byte(body), &rows)
		var out []string
		for _, r := range rows {
			out = append(out, str(r["node_name"]))
		}
		return out
	}

	prod := &rbac.Caller{UserID: "u", Role: "user", Accesses: []rbac.TeamAccess{{
		Levels: map[string]string{"proxies": "read"}, Perimeter: rbac.Perimeter{Labels: map[string]string{"env": "prod"}}}}}
	code, body := call(prod, "/api/v1/nodes")
	if got := names(body); code != 200 || len(got) != 2 || got[0] != "lan-1" || got[1] != "agent-lan" {
		t.Fatalf("un compte qui lit des proxys de production voit le groupe qui les sert et son Agent : %d %v", code, got)
	}
	if _, body := call(prod, "/api/v1/node-events"); len(names(body)) != 1 {
		t.Errorf("événements : %s", body)
	}
	if _, body := call(prod, "/api/v1/architecture/groups"); body != `{"paris-lan":[{"id":"e1"}]}` {
		t.Errorf("groupes : %s", body)
	}
	if code, _ := call(prod, "/api/v1/nodes/e1"); code != 200 {
		t.Errorf("nœud visible : %d", code)
	}
	if code, _ := call(prod, "/api/v1/nodes/e2"); code != 404 {
		t.Errorf("nœud d'un autre groupe : %d", code)
	}
	for _, p := range []string{"/api/v1/nodes/live", "/api/v1/backends/health", "/api/v1/edges/waf-status"} {
		if code, _ := call(prod, p); code != http.StatusForbidden {
			t.Errorf("%s : vue globale, %d", p, code)
		}
	}

	// Un accès à l'infrastructure désigne des groupes par leurs attributs.
	infra := &rbac.Caller{UserID: "i", Role: "user", Accesses: []rbac.TeamAccess{{
		Levels: map[string]string{"infra": "read"}, Perimeter: rbac.Perimeter{Group: rbac.GroupCriterion{Environment: "prod"}}}}}
	if _, body := call(infra, "/api/v1/nodes"); len(names(body)) != 2 || names(body)[0] != "net-1" {
		t.Errorf("infra sur les groupes de production : %v", names(body))
	}
	// Sans critère : toute la topologie. Un administrateur aussi.
	open := &rbac.Caller{UserID: "o", Role: "user", Accesses: []rbac.TeamAccess{{Levels: map[string]string{"infra": "read"}}}}
	if _, body := call(open, "/api/v1/nodes"); len(names(body)) != 5 {
		t.Errorf("infra sans critère : %v", names(body))
	}
	if code, _ := call(open, "/api/v1/nodes/live"); code != 200 {
		t.Errorf("vue globale ouverte à l'accès sans critère : %d", code)
	}
}
