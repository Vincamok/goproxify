// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

func prodRoute() *router.Route {
	return &router.Route{
		ID: "id-1", Name: "alpha-1", Host: "app.corp.io", Aliases: []string{"www.corp.io"},
		Backends: []router.Backend{{URL: "http://10.0.0.5:8080"}},
		Labels:   map[string]string{"env": "prod", "projet": "alpha"},
	}
}

func TestPerimeterCriteria(t *testing.T) {
	groups := []rbac.GroupRef{{Name: "paris-lan", Environment: "prod", Region: "paris", Tags: []string{"lan"}}}
	res := rbac.RouteResource(prodRoute(), groups)

	cases := []struct {
		name string
		p    rbac.Perimeter
		want bool
	}{
		{"périmètre vide = tout", rbac.Perimeter{}, true},
		{"domaine joker", rbac.Perimeter{Domain: "*.corp.io"}, true},
		{"domaine par alias", rbac.Perimeter{Domain: "www.corp.io"}, true},
		{"autre domaine", rbac.Perimeter{Domain: "*.other.io"}, false},
		{"identifiant exact", rbac.Perimeter{Proxy: "id-1"}, true},
		{"nom en glob", rbac.Perimeter{Proxy: "alpha-*"}, true},
		{"nom en glob raté", rbac.Perimeter{Proxy: "beta-*"}, false},
		{"nom en expression régulière", rbac.Perimeter{Proxy: `re:^alpha-\d+$`}, true},
		{"expression régulière non ancrée", rbac.Perimeter{Proxy: `re:alp`}, true},
		{"expression régulière ratée", rbac.Perimeter{Proxy: `re:^alpha-\d{3}$`}, false},
		{"backend", rbac.Perimeter{Backend: "http://10.0.0.*"}, true},
		{"backend raté", rbac.Perimeter{Backend: "http://192.168.*"}, false},
		{"groupe par nom", rbac.Perimeter{Group: rbac.GroupCriterion{Name: "paris-*"}}, true},
		{"groupe par environnement", rbac.Perimeter{Group: rbac.GroupCriterion{Environment: "prod"}}, true},
		{"groupe par région", rbac.Perimeter{Group: rbac.GroupCriterion{Region: "Paris"}}, true},
		{"groupe par étiquette", rbac.Perimeter{Group: rbac.GroupCriterion{Tag: "lan"}}, true},
		{"groupe : un même groupe réunit les attributs", rbac.Perimeter{Group: rbac.GroupCriterion{Environment: "test", Tag: "lan"}}, false},
		{"étiquette", rbac.Perimeter{Labels: map[string]string{"env": "prod"}}, true},
		{"étiquette de valeur différente", rbac.Perimeter{Labels: map[string]string{"env": "test"}}, false},
		{"étiquette absente", rbac.Perimeter{Labels: map[string]string{"equipe": "x"}}, false},
		{"toutes les étiquettes sont requises", rbac.Perimeter{Labels: map[string]string{"env": "prod", "projet": "beta"}}, false},
		{"critères en ET : tous retenus", rbac.Perimeter{Domain: "*.corp.io", Labels: map[string]string{"env": "prod"}, Group: rbac.GroupCriterion{Tag: "lan"}}, true},
		{"critères en ET : un seul raté suffit à exclure", rbac.Perimeter{Domain: "*.corp.io", Labels: map[string]string{"env": "test"}}, false},
	}
	for _, c := range cases {
		if got := c.p.Matches(res); got != c.want {
			t.Errorf("%s : %v, attendu %v", c.name, got, c.want)
		}
	}
}

// Un critère posé sur une dimension que la ressource n'a pas ne la couvre pas.
func TestPerimeterNeverCoversAResourceWithoutTheDimension(t *testing.T) {
	bare := rbac.RouteResource(&router.Route{ID: "x", Host: "bare.io"}, nil)
	for name, p := range map[string]rbac.Perimeter{
		"étiquette": {Labels: map[string]string{"env": "prod"}},
		"groupe":    {Group: rbac.GroupCriterion{Name: "*"}},
		"backend":   {Backend: "*"},
	} {
		if p.Matches(bare) {
			t.Errorf("%s : couvre une ressource qui n'en a pas", name)
		}
	}
}

func TestProxyNameDefaultsToTheHost(t *testing.T) {
	r := &router.Route{ID: "x", Host: "shop.corp.io"}
	if rbac.ProxyName(r) != "shop.corp.io" {
		t.Fatalf("nom par défaut : %q", rbac.ProxyName(r))
	}
	if !(rbac.Perimeter{Proxy: "shop.*"}).Matches(rbac.RouteResource(r, nil)) {
		t.Fatal("un proxy sans nom se désigne par son hôte")
	}
}

func TestPerimeterValidate(t *testing.T) {
	for _, bad := range []rbac.Perimeter{
		{Proxy: "re:("},
		{Proxy: "re:"},
		{Proxy: "[abc"},
		{Domain: "[x"},
		{Backend: "[x"},
		{Group: rbac.GroupCriterion{Name: "[x"}},
		{Labels: map[string]string{"Env": "prod"}},
		{Labels: map[string]string{"env": "a b"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Errorf("%+v : devrait être refusé", bad)
		}
	}
	good := rbac.Perimeter{Domain: "*.corp.io", Proxy: `re:^a\d+$`, Backend: "http://10.*", Labels: map[string]string{"env": "prod"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
}

func TestParseLabelSelector(t *testing.T) {
	if k, v, err := rbac.ParseLabelSelector("env=prod"); err != nil || k != "env" || v != "prod" {
		t.Fatalf("%q %q %v", k, v, err)
	}
	for _, bad := range []string{"env", "=prod", "Env=prod", "env=a b"} {
		if _, _, err := rbac.ParseLabelSelector(bad); err == nil {
			t.Errorf("%q devrait être refusé", bad)
		}
	}
}

func TestValidateLabelsBoundsTheCount(t *testing.T) {
	many := map[string]string{}
	for i := 0; i < 33; i++ {
		many["k"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	if err := rbac.ValidateLabels(many); err == nil {
		t.Fatal("33 étiquettes devraient être refusées")
	}
}

// Les groupes qui servent une route sont ceux dont une passerelle reçoit cette route d'après son jeton.
func TestGroupsServingARouteFollowTheGatewayScopes(t *testing.T) {
	store := archstore.New(t.TempDir())
	cluster := func(group string) []byte { return []byte(`{"cluster":true,"cluster_group":"` + group + `"}`) }
	for _, n := range []archstore.NodeEntry{
		{ID: "e1", Role: "edge", Name: "paris-lan-1", Config: cluster("paris-lan"), RBACRole: "viewer",
			Scopes: []archstore.ScopeEntry{{ID: "s1", Type: "domain", Value: "*.corp.io"}}},
		{ID: "e2", Role: "edge", Name: "paris-lan-2", Config: cluster("paris-lan"), RBACRole: "viewer",
			Scopes: []archstore.ScopeEntry{{ID: "s2", Type: "domain", Value: "*.corp.io"}}},
		{ID: "e3", Role: "edge", Name: "internet-1", Config: cluster("internet"), RBACRole: "viewer",
			Scopes: []archstore.ScopeEntry{{ID: "s3", Type: "domain", Value: "*.public.io"}}},
		{ID: "e4", Role: "edge", Name: "solo", Environment: "test", Region: "lyon"},
		{ID: "a1", Role: "agent", Name: "agent-1"},
	} {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.SetGroupAttributes("paris-lan", archstore.GroupAttributes{Environment: "prod", Region: "paris", Tags: []string{"lan"}}); err != nil {
		t.Fatal(err)
	}

	snap := rbac.ArchitectureGroups{Store: store}.Snapshot()
	got := snap.GroupsServing(&router.Route{ID: "p", Host: "app.corp.io"})
	if len(got) != 2 || got[0].Name != "paris-lan" || got[0].Environment != "prod" || got[0].Region != "paris" || len(got[0].Tags) != 1 || got[1].Name != "solo" {
		t.Fatalf("groupes servant app.corp.io : %+v", got)
	}
	// « solo » n'est dans aucun groupe : c'est un groupe d'un membre, et son jeton sans limite (rôle admin) lui fait recevoir toutes les routes.
	got = snap.GroupsServing(&router.Route{ID: "q", Host: "x.public.io"})
	names := []string{}
	for _, g := range got {
		names = append(names, g.Name)
	}
	if len(names) != 2 || names[0] != "internet" || names[1] != "solo" {
		t.Fatalf("groupes servant x.public.io : %v", names)
	}
	for _, g := range got {
		if g.Name == "solo" && (g.Environment != "test" || g.Region != "lyon") {
			t.Fatalf("la passerelle isolée porte ses propres attributs : %+v", g)
		}
	}
	// Le groupe LAN ne sert pas le domaine d'internet : un droit sur lui n'ouvre pas ce proxy.
	lan := rbac.Perimeter{Group: rbac.GroupCriterion{Name: "paris-lan"}}
	if lan.Matches(rbac.RouteResource(&router.Route{ID: "q", Host: "x.public.io"}, got)) {
		t.Fatal("le groupe paris-lan ne sert pas x.public.io")
	}
}

func TestGroupAttributesSurviveAGroupCardUpdate(t *testing.T) {
	store := archstore.New(t.TempDir())
	if err := store.SetGroupAttributes("g", archstore.GroupAttributes{Environment: "prod", Tags: []string{"lan"}}); err != nil {
		t.Fatal(err)
	}
	if err := store.SetGroupCard("g", 3, "abc"); err != nil {
		t.Fatal(err)
	}
	a := store.GroupAttributesOf("g")
	if a.Environment != "prod" || len(a.Tags) != 1 {
		t.Fatalf("attributs perdus à la mise à jour de la fiche : %+v", a)
	}
	if v, h := store.GroupCardVersion("g"); v != 3 || h != "abc" {
		t.Fatalf("fiche : %d %q", v, h)
	}
}

func TestEngineScopeAndCan(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "e.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t.local','x','user')`,
		`INSERT INTO users (id, email, password_hash, role) VALUES ('a','a@t.local','x','admin')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	eng := rbac.Engine{DB: db}
	res := rbac.RouteResource(prodRoute(), nil)

	if !eng.Can(ctx, "a", "proxies:manage", res) {
		t.Fatal("un administrateur peut tout")
	}
	if eng.Can(ctx, "u", "proxies:read", res) || !eng.Scope(ctx, "u", "proxies:read").None() {
		t.Fatal("sans équipe, rien")
	}

	grantViaTeam(t, db, "u", "domain", "*.corp.io", "read")
	grantViaTeam(t, db, "u", "proxy", "alpha-*", "write")
	if !eng.Can(ctx, "u", "proxies:read", res) {
		t.Fatal("lecture par le domaine")
	}
	if !eng.Can(ctx, "u", "proxies:operate", res) {
		t.Fatal("écriture par le nom du proxy")
	}
	other := rbac.RouteResource(&router.Route{ID: "o", Name: "beta-1", Host: "x.corp.io"}, nil)
	if eng.Can(ctx, "u", "proxies:operate", other) {
		t.Fatal("l'écriture ne s'étend pas au domaine : seul l'accès par nom est en écriture")
	}
	if !eng.Can(ctx, "u", "proxies:read", other) {
		t.Fatal("la lecture s'étend au domaine")
	}
	for _, perm := range []string{"proxies:manage", "proxies:import", "surface:enforce", "domains:manage", "certs:read", "logs:read", "portal_catalog:manage", "inconnue"} {
		if eng.Can(ctx, "u", perm, res) {
			t.Errorf("%s : aucun accès d'équipe actuel ne la donne", perm)
		}
	}
}

// L'accès « passerelle » ne vaut plus « tout » : il se limite aux proxys que le groupe sert (ADR 0022, constat 3).
func TestEdgeGrantIsNowAGroupCriterion(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t.local','x','user')`); err != nil {
		t.Fatal(err)
	}
	grantViaTeam(t, db, "u", "edge", "paris-lan", "read")

	store := archstore.New(t.TempDir())
	cluster := func(group string) []byte { return []byte(`{"cluster":true,"cluster_group":"` + group + `"}`) }
	for _, n := range []archstore.NodeEntry{
		{ID: "e1", Role: "edge", Name: "lan-1", Config: cluster("paris-lan"), RBACRole: "viewer", Scopes: []archstore.ScopeEntry{{ID: "s1", Type: "domain", Value: "*.corp.io"}}},
		{ID: "e3", Role: "edge", Name: "net-1", Config: cluster("internet"), RBACRole: "viewer", Scopes: []archstore.ScopeEntry{{ID: "s3", Type: "domain", Value: "*.public.io"}}},
	} {
		if err := store.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	groups := rbac.ArchitectureGroups{Store: store}.Snapshot()
	eng := rbac.Engine{DB: db}
	if !eng.CanRoute(ctx, "u", "proxies:read", &router.Route{ID: "a", Host: "app.corp.io"}, groups) {
		t.Fatal("le groupe paris-lan sert app.corp.io")
	}
	if eng.CanRoute(ctx, "u", "proxies:read", &router.Route{ID: "b", Host: "www.public.io"}, groups) {
		t.Fatal("le groupe internet n'est pas celui de l'accès")
	}
}
