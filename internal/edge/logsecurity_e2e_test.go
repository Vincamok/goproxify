// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// addSecurity et addPlain écrivent des accès directement dans la base de la passerelle.
func (g *streamGateway) addAccess(prefix string, n int, flagged bool) {
	for i := 1; i <= n; i++ {
		e := logstore.Entry{Ts: time.Now().Add(time.Duration(i) * time.Millisecond), Level: "info", Component: "edge", Domain: "app.example.com",
			Method: "GET", Path: fmt.Sprintf("/%s/%d", prefix, i), Status: 200, IP: "198.51.100.7"}
		if flagged {
			e.Status, e.WAFMatches = 403, []string{"sqli"}
		}
		g.logStore.Add(logstore.KindAccess, e)
	}
	g.logStore.Flush()
}

// L'Admin ne reçoit que les événements de sécurité : les accès ordinaires restent dans la base de la passerelle, le
// curseur avance quand même, et rien ne se perd ni ne se double à travers une coupure.
func TestSecurityOnlyStreamKeepsOrdinaryAccessOnTheGateway(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	gw.addAccess("ordinaire", 300, false)
	gw.addAccess("attaque", 5, true)
	gw.addAccess("ordinaire2", 100, false)
	admin.start(t, gw.url)
	waitUntil(t, "les 5 événements de sécurité", func() bool { return admin.count(t, `path LIKE '/attaque/%'`) == 5 })
	waitUntil(t, "le curseur à la fin de la base", func() bool {
		c, _ := admin.store.StreamCursor(streamEdgeID, "access")
		return c == gw.logStore.LastID(logstore.KindAccess)
	})
	if n := admin.count(t, `path LIKE '/ordinaire%'`); n != 0 {
		t.Fatalf("%d accès ordinaires reçus", n)
	}

	// Une coupure : des événements arrivent pendant ce temps, les accès ordinaires aussi.
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })
	gw.addAccess("ordinaire3", 50, false)
	gw.addAccess("attaque2", 3, true)
	admin.start(t, gw.url)
	waitUntil(t, "les 3 événements de la coupure", func() bool { return admin.count(t, `path LIKE '/attaque2/%'`) == 3 })
	if n := admin.count(t, `path LIKE '/attaque/%'`); n != 5 {
		t.Errorf("%d événements d'avant la coupure, attendu 5 (doublons ou pertes)", n)
	}
	if n := admin.count(t, `path LIKE '/ordinaire%'`); n != 0 {
		t.Errorf("%d accès ordinaires reçus après la reprise", n)
	}

	// Le curseur a dépassé les lignes écartées, c'est voulu : elles restent consultables sur la passerelle.
	if n, _ := gw.logStore.Search(t.Context(), logstore.Query{Kinds: []logstore.Kind{logstore.KindAccess}, Path: "/ordinaire", Limit: 1000}); len(n.Rows) != 450 {
		t.Errorf("la passerelle garde %d accès ordinaires, attendu 450", len(n.Rows))
	}
}

// Une vue Live ouverte fait envoyer par la passerelle ses nouvelles lignes, sans qu'elles soient enregistrées ;
// sans vue ouverte, la passerelle n'envoie rien.
func TestLiveViewReceivesGatewayRowsOnDemand(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	admin.start(t, gw.url)
	waitUntil(t, "la connexion de la passerelle", func() bool { return gw.wsHub.HasAdmin(streamEdgeID) })

	_, ch, cancel := admin.store.Subscribe()
	defer cancel()
	gw.addAccess("sans-vue", 5, false)
	select {
	case e := <-ch:
		t.Fatalf("ligne reçue sans vue Live : %s", e.Path)
	case <-time.After(700 * time.Millisecond):
	}

	release := admin.manager.AcquireLive()
	defer release()
	waitUntil(t, "l'abonnement de la passerelle", func() bool {
		gw.logLive.mu.Lock()
		defer gw.logLive.mu.Unlock()
		return len(gw.logLive.subs) == 1
	})
	gw.addAccess("en-direct", 6, false)
	seen := map[string]bool{}
	deadline := time.After(10 * time.Second)
	for len(seen) < 6 {
		select {
		case e := <-ch:
			seen[e.Path] = true
		case <-deadline:
			t.Fatalf("%d lignes reçues sur 6 : %v", len(seen), seen)
		}
	}
	if n := admin.count(t, `path LIKE '/en-direct/%'`); n != 0 {
		t.Errorf("%d lignes Live enregistrées : elles ne doivent que passer", n)
	}
	if seen["/sans-vue/1"] {
		t.Error("une ligne d'avant l'ouverture de la vue est arrivée")
	}
}

// La passerelle annonce son débit récent à l'Admin, qui le sert à la carte de topologie.
func TestGatewayReportsItsRecentTrafficToTheAdmin(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	admin.start(t, gw.url)
	waitUntil(t, "la connexion de la passerelle", func() bool { return gw.wsHub.HasAdmin(streamEdgeID) })
	gw.addAccess("ordinaire", 30, false)
	gw.addAccess("attaque", 4, true) // 403 : refusées

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go gw.trafficLoop(ctx)
	waitUntil(t, "le débit annoncé", func() bool {
		req, blocked, _, ok := admin.manager.RecentTraffic("gw-stream")
		return ok && req == 34 && blocked == 4
	})
}

// Une passerelle restaurée sans son dossier de logs (la sauvegarde d'état ne le reprend pas) a une base neuve dont les
// lignes sont numérotées depuis 1, alors que l'Admin a enregistré une position bien plus haute : sans correction il les
// prendrait pour déjà reçues. Il repart du début de la nouvelle base, sans rien redemander de l'ancienne.
func TestAGatewayRestoredWithoutItsLogsIsNotMistakenForAlreadyServed(t *testing.T) {
	dir := t.TempDir()
	gwDir := filepath.Join(dir, "gw")
	gw := newStreamGateway(t, gwDir)
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)

	admin.start(t, gw.url)
	gw.addAccess("avant", 30, true)
	waitUntil(t, "les 30 événements d'avant", func() bool { return admin.count(t, `path LIKE '/avant/%'`) == 30 })
	before, _ := admin.store.StreamCursor(streamEdgeID, "access")
	if before == 0 {
		t.Fatal("position du flux d'accès non enregistrée")
	}
	admin.stop()
	waitUntil(t, "déconnexion de l'Admin", func() bool { return !gw.wsHub.HasAdmin(streamEdgeID) })

	// Disque neuf : le volume d'état est restauré, pas le dossier des logs.
	gw.logStreams.stopAll()
	_ = gw.logStore.Close()
	if err := os.RemoveAll(filepath.Join(gwDir, "logs")); err != nil {
		t.Fatal(err)
	}
	gw2 := newStreamGateway(t, gwDir)
	gw2.addAccess("apres", 5, true) // numérotées 1 à 5, sous la position de l'Admin
	admin.start(t, gw2.url)
	waitUntil(t, "les 5 événements de la base neuve", func() bool { return admin.count(t, `path LIKE '/apres/%'`) == 5 })
	if n := admin.count(t, `path LIKE '/avant/%'`); n != 30 {
		t.Errorf("%d événements d'avant, attendu 30 (aucun rejeu de l'ancienne base)", n)
	}
	gw2.addAccess("encore", 3, true)
	waitUntil(t, "le flux en direct après la remise à zéro", func() bool { return admin.count(t, `path LIKE '/encore/%'`) == 3 })
	if after, _ := admin.store.StreamCursor(streamEdgeID, "access"); after >= before {
		t.Errorf("la position n'a pas été ramenée : %d (avant %d)", after, before)
	}
}
