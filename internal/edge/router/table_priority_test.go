// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router_test

import (
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func owner(t *testing.T, tbl *router.Table, host string) string {
	t.Helper()
	r, ok := tbl.ByHost(host)
	if !ok {
		return ""
	}
	return r.ID
}

func TestTablePriority_ConfiguredBeatsDiscoveredInEitherOrder(t *testing.T) {
	for _, discoveredFirst := range []bool{true, false} {
		var tbl router.Table
		d, m := route("docker-host:app.example.fr", "app.example.fr"), route("proxy-1", "app.example.fr")
		if discoveredFirst {
			tbl.Upsert(d)
			tbl.Upsert(m)
		} else {
			tbl.Upsert(m)
			tbl.Upsert(d)
		}
		if got := owner(t, &tbl, "app.example.fr"); got != "proxy-1" {
			t.Fatalf("discoveredFirst=%v : le proxy configuré doit servir l'hôte, obtenu %q", discoveredFirst, got)
		}
		if tbl.Len() != 2 {
			t.Fatalf("la route découverte reste dans la table, len=%d", tbl.Len())
		}
	}
}

func TestTablePriority_ReplaceIgnoresOrder(t *testing.T) {
	var tbl router.Table
	if err := tbl.Replace([]*router.Route{route("proxy-1", "app.example.fr"), route("k8s:ns/app", "app.example.fr")}); err != nil {
		t.Fatal(err)
	}
	if got := owner(t, &tbl, "app.example.fr"); got != "proxy-1" {
		t.Fatalf("obtenu %q", got)
	}
}

func TestTablePriority_DeleteRestoresDiscovered(t *testing.T) {
	var tbl router.Table
	tbl.Upsert(route("docker-host:app.example.fr", "app.example.fr"))
	tbl.Upsert(route("proxy-1", "app.example.fr"))
	tbl.Delete("proxy-1")
	if got := owner(t, &tbl, "app.example.fr"); got != "docker-host:app.example.fr" {
		t.Fatalf("la route des labels doit reprendre l'hôte, obtenu %q", got)
	}
}

func TestTablePriority_DeletingDiscoveredKeepsConfigured(t *testing.T) {
	var tbl router.Table
	tbl.Upsert(route("proxy-1", "app.example.fr"))
	tbl.Upsert(route("docker-host:app.example.fr", "app.example.fr"))
	tbl.Delete("docker-host:app.example.fr")
	if got := owner(t, &tbl, "app.example.fr"); got != "proxy-1" {
		t.Fatalf("l'arrêt du conteneur ne doit pas retirer le proxy de l'hôte, obtenu %q", got)
	}
}

func TestTablePriority_ShadowedBy(t *testing.T) {
	var tbl router.Table
	d := route("docker-host:app.example.fr", "app.example.fr")
	tbl.Upsert(d)
	if _, ok := tbl.ShadowedBy(d); ok {
		t.Fatal("seule, la route des labels n'est remplacée par personne")
	}
	tbl.Upsert(route("proxy-1", "app.example.fr"))
	if id, ok := tbl.ShadowedBy(d); !ok || id != "proxy-1" {
		t.Fatalf("ShadowedBy = %q %v", id, ok)
	}
	tbl.Delete("proxy-1")
	if _, ok := tbl.ShadowedBy(d); ok {
		t.Fatal("proxy supprimé ou désactivé : la route des labels n'est plus remplacée")
	}
}

func TestTablePriority_AliasHandoff(t *testing.T) {
	var tbl router.Table
	d := route("docker-host:a.example.fr", "a.example.fr")
	d.Aliases = []string{"b.example.fr"}
	tbl.Upsert(d)
	tbl.Upsert(route("proxy-1", "b.example.fr"))
	if got := owner(t, &tbl, "a.example.fr"); got != d.ID {
		t.Fatalf("a: %q", got)
	}
	if got := owner(t, &tbl, "b.example.fr"); got != "proxy-1" {
		t.Fatalf("b: %q", got)
	}
	tbl.Upsert(route("proxy-1", "c.example.fr"))
	if got := owner(t, &tbl, "b.example.fr"); got != d.ID {
		t.Fatalf("l'alias libéré doit revenir à la route des labels, obtenu %q", got)
	}
}
