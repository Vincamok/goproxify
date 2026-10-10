// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router_test

import (
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func route(id, host string) *router.Route {
	return &router.Route{
		ID:        id,
		Host:      host,
		Type:      router.RouteHTTP,
		Backends:  []router.Backend{{URL: "http://127.0.0.1:3000"}},
		UpdatedAt: time.Now(),
	}
}

func TestTableUpsertByHost(t *testing.T) {
	var tbl router.Table
	tbl.Upsert(route("r1", "app.example.fr"))
	r, ok := tbl.ByHost("app.example.fr")
	if !ok || r.ID != "r1" {
		t.Fatalf("route non trouvée par host")
	}
	if tbl.Len() != 1 {
		t.Fatalf("len attendu 1, obtenu %d", tbl.Len())
	}
}

func TestTableDelete(t *testing.T) {
	var tbl router.Table
	tbl.Upsert(route("r1", "app.example.fr"))
	tbl.Delete("r1")
	_, ok := tbl.ByHost("app.example.fr")
	if ok {
		t.Fatal("route toujours présente après suppression")
	}
	if tbl.Len() != 0 {
		t.Fatalf("len attendu 0, obtenu %d", tbl.Len())
	}
}

func TestTableReplace(t *testing.T) {
	var tbl router.Table
	tbl.Upsert(route("r1", "a.example.fr"))
	tbl.Upsert(route("r2", "b.example.fr"))

	if err := tbl.Replace([]*router.Route{route("r3", "c.example.fr")}); err != nil {
		t.Fatal(err)
	}
	if tbl.Len() != 1 {
		t.Fatalf("len attendu 1 après Replace, obtenu %d", tbl.Len())
	}
	_, ok := tbl.ByHost("a.example.fr")
	if ok {
		t.Fatal("ancienne route toujours présente après Replace")
	}
	_, ok = tbl.ByHost("c.example.fr")
	if !ok {
		t.Fatal("nouvelle route absente après Replace")
	}
}

// Revue P1 #11 — Replace ne doit pas laisser la table vide/partielle si une route est invalide.
func TestReviewP1_TableReplaceEmptyIDPreservesPrevious(t *testing.T) {
	var tbl router.Table
	tbl.Upsert(route("r1", "a.example.fr"))
	tbl.Upsert(route("r2", "b.example.fr"))

	err := tbl.Replace([]*router.Route{
		route("r3", "c.example.fr"),
		{ID: "", Host: "bad.example.fr", Type: router.RouteHTTP, Backends: []router.Backend{{URL: "http://127.0.0.1:9"}}},
	})
	if err == nil {
		t.Fatal("Replace avec ID vide doit retourner une erreur")
	}

	// Comportement attendu (atomique) : l'ancienne table reste intacte.
	if _, ok := tbl.ByHost("a.example.fr"); !ok {
		t.Fatal("host a.example.fr doit rester routable après Replace échoué")
	}
	if _, ok := tbl.ByHost("b.example.fr"); !ok {
		t.Fatal("host b.example.fr doit rester routable après Replace échoué")
	}
	if _, ok := tbl.ByHost("c.example.fr"); ok {
		t.Fatal("Replace partiel ne doit pas publier r3 si le lot a échoué")
	}
	if tbl.Len() != 2 {
		t.Fatalf("len attendu 2 (table précédente), obtenu %d", tbl.Len())
	}
}

func TestTableByHostAliasesAndCase(t *testing.T) {
	var tbl router.Table
	r := route("r1", "App.Example.fr")
	r.Aliases = []string{"WWW.example.fr"}
	tbl.Upsert(r)
	if _, ok := tbl.ByHost("app.example.fr"); !ok {
		t.Fatal("host principal insensible à la casse")
	}
	if got, ok := tbl.ByHost("www.example.fr"); !ok || got.ID != "r1" {
		t.Fatal("alias non routé")
	}
}

func TestPassthroughRoutePrefersWildcardDelegation(t *testing.T) {
	var tbl router.Table
	exact := route("proxy-api", "api.example.com")
	exact.TLSPassthrough = false
	tbl.Upsert(exact)

	deleg := route("deleg-1", "*.example.com")
	deleg.TLSPassthrough = true
	deleg.Backends = []router.Backend{{URL: "203.0.113.91:443"}}
	tbl.Upsert(deleg)

	// ByHost privilégie l'exact → passthrough ignoré (ancien bug).
	r, ok := tbl.ByHost("api.example.com")
	if !ok || r.ID != "proxy-api" {
		t.Fatalf("ByHost devrait renvoyer le proxy exact, got %#v ok=%v", r, ok)
	}

	pt, ok := tbl.PassthroughRoute("other.example.com")
	if !ok || pt.ID != "deleg-1" {
		t.Fatalf("PassthroughRoute devrait renvoyer la délégation, got %#v ok=%v", pt, ok)
	}
}

func TestTableByPort(t *testing.T) {
	var tbl router.Table
	r := &router.Route{
		ID:         "tcp1",
		Type:       router.RouteTCP,
		ListenPort: 5432,
		Backends:   []router.Backend{{URL: "10.0.0.1:5432"}},
		UpdatedAt:  time.Now(),
	}
	tbl.Upsert(r)
	got, ok := tbl.ByPort(5432)
	if !ok || got.ID != "tcp1" {
		t.Fatal("route TCP non trouvée par port")
	}
}

// Replace publie un contenu neuf d'un coup : des lecteurs concurrents ne voient jamais un hôte disparaître
// pendant qu'il reste dans toutes les versions, et un Upsert concurrent n'est pas perdu dans la table remplacée.
func TestTable_ConcurrentReplaceUpsertAndLookups(t *testing.T) {
	var tb router.Table
	mk := func(id, host string) *router.Route {
		return &router.Route{ID: id, Host: host, Aliases: []string{"alias-" + id + ".exemple.fr"}}
	}
	base := []*router.Route{mk("a", "a.exemple.fr"), mk("b", "b.exemple.fr")}
	if err := tb.Replace(base); err != nil {
		t.Fatal(err)
	}
	stop := make(chan struct{})
	var wg sync.WaitGroup
	var missing atomic.Int64
	for i := 0; i < 4; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-stop:
					return
				default:
				}
				if _, ok := tb.ByHost("a.exemple.fr"); !ok {
					missing.Add(1)
				}
				if _, ok := tb.ByHost("alias-b.exemple.fr"); !ok {
					missing.Add(1)
				}
				_ = tb.All()
				_ = tb.Len()
				tb.ByID("a")
			}
		}()
	}
	for i := 0; i < 300; i++ {
		_ = tb.Replace(base)
		tb.Upsert(mk("a", "a.exemple.fr")) // remplace la route avec les mêmes hôtes
		tb.Upsert(mk("c", fmt.Sprintf("c%d.exemple.fr", i%3)))
		tb.Delete("c")
	}
	close(stop)
	wg.Wait()
	if n := missing.Load(); n != 0 {
		t.Errorf("%d lectures ont vu disparaître un hôte qui existe dans toutes les versions", n)
	}
	if got := tb.Len(); got != 2 {
		t.Errorf("Len = %d, attendu 2", got)
	}
}

func TestTable_UpsertKeepsSharedHostsAndDropsStaleOnes(t *testing.T) {
	var tb router.Table
	tb.Upsert(&router.Route{ID: "a", Host: "a.fr", Aliases: []string{"old.fr"}, ListenPort: 0})
	tb.Upsert(&router.Route{ID: "a", Host: "a.fr", Aliases: []string{"new.fr"}})
	if _, ok := tb.ByHost("old.fr"); ok {
		t.Error("un alias retiré doit disparaître")
	}
	if _, ok := tb.ByHost("new.fr"); !ok {
		t.Error("le nouvel alias doit être présent")
	}
	tb.Upsert(&router.Route{ID: "t", Type: "tcp", ListenPort: 5432})
	tb.Upsert(&router.Route{ID: "t", Type: "tcp", ListenPort: 5433})
	if _, ok := tb.ByPort(5432); ok {
		t.Error("l'ancien port doit être libéré")
	}
	if _, ok := tb.ByPort(5433); !ok {
		t.Error("le nouveau port doit être présent")
	}
}
