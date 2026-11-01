// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Les droits d'un utilisateur ne viennent que de ses équipes ; un administrateur voit toujours tout.
func TestUserEffectiveGrantsAndCanProxy(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "g.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	route := &router.Route{ID: "p1", Host: "api.example.io"}

	must := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}

	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t.local','x','user')`)
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('a','a@t.local','x','admin')`)

	if rbac.CanReadProxy(ctx, db, "u", route) || rbac.CanWriteProxy(ctx, db, "u", route) {
		t.Fatal("user sans équipe ne doit rien pouvoir")
	}
	if !rbac.CanReadProxy(ctx, db, "a", route) || !rbac.CanWriteProxy(ctx, db, "a", route) {
		t.Fatal("admin doit tout pouvoir")
	}

	team := grantViaTeam(t, db, "u", "domain", "*.example.io", "read")
	if !rbac.CanReadProxy(ctx, db, "u", route) {
		t.Fatal("accès read d'une équipe doit permettre la lecture")
	}
	if rbac.CanWriteProxy(ctx, db, "u", route) {
		t.Fatal("accès read ne doit pas permettre l'écriture")
	}

	must(`UPDATE team_accesses SET levels='{"proxies":"operate","containers":"operate","surface":"learn","domains":"read"}' WHERE team_id=?`, team)
	if !rbac.CanWriteProxy(ctx, db, "u", route) {
		t.Fatal("accès write doit permettre l'écriture")
	}
	if rbac.CanDeleteProxy(ctx, db, "u", route) {
		t.Fatal("la suppression d'un proxy reste réservée aux administrateurs")
	}

	// Deux équipes, même périmètre : les accès s'additionnent, le niveau le plus haut l'emporte.
	must(`INSERT INTO users (id, email, password_hash, role) VALUES ('m','m@t.local','x','user')`)
	grantViaTeam(t, db, "m", "domain", "*.example.io", "read")
	grantViaTeam(t, db, "m", "domain", "*.example.io", "write")
	grants, err := rbac.UserEffectiveGrants(ctx, db, "m")
	if err != nil {
		t.Fatal(err)
	}
	if len(grants) != 2 || !rbac.CanWriteProxy(ctx, db, "m", route) {
		t.Fatalf("les accès des deux équipes s'additionnent, l'exploitation l'emporte : %#v", grants)
	}

	// Un administrateur membre d'une équipe à périmètre étroit n'est pas restreint pour autant.
	grantViaTeam(t, db, "a", "domain", "*.other.io", "read")
	if !rbac.CanReadProxy(ctx, db, "a", route) || !rbac.CanWriteProxy(ctx, db, "a", route) || !rbac.CanDeleteProxy(ctx, db, "a", route) {
		t.Fatal("les équipes ne restreignent pas un administrateur")
	}
}

// L'accès effectif dit d'où vient chaque droit ; un administrateur est global et ses équipes n'ajoutent aucun accès.
func TestEffectiveAccessGivesTheOriginOfEachRight(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctx := context.Background()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t','x','user'), ('a','a@t','x','admin'), ('s','s@t','x','superadmin')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	grantViaTeam(t, db, "u", "domain", "*.example.io", "read")
	grantViaTeam(t, db, "u", "domain", "*.example.io", "write")
	grantViaTeam(t, db, "a", "domain", "*.example.io", "read")

	acc, err := rbac.EffectiveAccess(ctx, db, "u")
	if err != nil {
		t.Fatal(err)
	}
	if acc.Global || len(acc.Teams) != 2 || len(acc.Teams[0].Accesses) != 1 || len(acc.Teams[1].Accesses) != 1 {
		t.Fatalf("user : %+v", acc)
	}
	if !slices.Contains(acc.Granted, "proxies:operate") || !slices.Contains(acc.Granted, "domains:read") || slices.Contains(acc.Granted, "proxies:manage") {
		t.Fatalf("permissions du catalogue portées par les accès : %v", acc.Granted)
	}
	if len(acc.Permissions) != 0 {
		t.Fatalf("un user sans équipe DPO n'a aucune capacité : %+v", acc.Permissions)
	}

	adm, err := rbac.EffectiveAccess(ctx, db, "a")
	if err != nil {
		t.Fatal(err)
	}
	if !adm.Global || len(adm.Granted) != 0 {
		t.Fatalf("un administrateur est global, sans accès par équipe : %+v", adm)
	}
	viaRole := map[string]string{}
	for _, p := range adm.Permissions {
		viaRole[p.Permission] = p.ViaRole
	}
	if viaRole[rbac.PermGDPRExport] != "admin" || viaRole[rbac.PermGDPRErase] != "admin" || viaRole[rbac.PermGDPRReveal] != "" {
		t.Fatalf("l'administrateur garde l'export et l'effacement, pas la révélation : %+v", adm.Permissions)
	}

	sup, _ := rbac.EffectiveAccess(ctx, db, "s")
	if len(sup.Permissions) != len(rbac.KnownPermissions) {
		t.Fatalf("le superadmin détient toutes les capacités : %+v", sup.Permissions)
	}
}
