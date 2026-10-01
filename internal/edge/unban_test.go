// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"testing"
	"time"

	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
	"github.com/vincamok/goproxify/internal/edge/threat"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestAdminUnbanLiftsBanPostedByTheGateway(t *testing.T) {
	n := newBanNode(t, "frontal")
	const ip = "203.0.113.20"
	if err := n.srv.bansDB.UpsertBan("f2b-uuid", ip, "", "Fail2Ban: trop d'erreurs", "fail2ban", nil); err != nil {
		t.Fatal(err)
	}
	n.srv.reloadBanStore()

	// La liste de l'Admin ne remplace que ses propres bans : sans déban explicite, l'IP resterait bloquée.
	n.srv.applyBans(nil)
	if !n.blocked(ip) {
		t.Fatal("prérequis : un ban posé par la passerelle survit à la liste de l'Admin")
	}

	n.srv.applyUnbans([]edgews.UnbanEntry{{IP: ip}})
	n.srv.applyBans(nil)
	if n.blocked(ip) {
		t.Fatal("le déban Admin doit lever le ban Fail2Ban local")
	}
	n.srv.loadBansFromDisk()
	if n.blocked(ip) {
		t.Fatal("le déban doit survivre à un redémarrage")
	}
}

func TestUnbanReplayKeepsBansPostedAfterIt(t *testing.T) {
	n := newBanNode(t, "frontal")
	const ip = "203.0.113.21"
	if err := n.srv.bansDB.UpsertBan("f2b-recent", ip, "", "", "fail2ban", nil); err != nil {
		t.Fatal(err)
	}
	n.srv.reloadBanStore()

	past := time.Now().Add(-time.Hour)
	n.srv.applyUnbans([]edgews.UnbanEntry{{IP: ip, At: &past}})
	if !n.blocked(ip) {
		t.Fatal("un ban posé après le déban rejoué doit rester")
	}
}

func TestWhitelistOverridesExistingAutomaticBans(t *testing.T) {
	n := newBanNode(t, "frontal")
	const f2bIP, sentinelIP, manualIP = "203.0.113.30", "203.0.113.31", "203.0.113.32"
	for _, b := range []struct{ id, ip, src string }{
		{"f2b", f2bIP, "fail2ban"},
		{"threat-" + sentinelIP, sentinelIP, "threat"},
		{"manuel", manualIP, "admin"},
	} {
		if err := n.srv.bansDB.UpsertBan(b.id, b.ip, "", "", b.src, nil); err != nil {
			t.Fatal(err)
		}
	}
	n.srv.reloadBanStore()
	if !n.blocked(f2bIP) || !n.blocked(sentinelIP) || !n.blocked(manualIP) {
		t.Fatal("prérequis : les trois IPs sont bannies")
	}

	n.srv.f2bEngine = edgef2b.New()
	n.srv.f2bEngine.UpdateConfig(edgef2b.Config{Enabled: true, Whitelist: []string{f2bIP, manualIP}})
	n.srv.threatEngine = threat.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	n.srv.threatEngine.UpdateConfig(threat.Config{Whitelist: threat.Whitelist{IPs: []string{"203.0.113.31/32"}}})
	n.srv.reloadBanStore()

	if n.blocked(f2bIP) {
		t.Fatal("la liste blanche Fail2Ban doit lever un ban Fail2Ban déjà posé")
	}
	if n.blocked(sentinelIP) {
		t.Fatal("la liste blanche Sentinel doit lever un ban Sentinel déjà posé")
	}
	if !n.blocked(manualIP) {
		t.Fatal("un ban manuel reste appliqué même si l'IP est en liste blanche Fail2Ban")
	}
}

func TestFail2BanIgnoresForbiddenServedByABan(t *testing.T) {
	n := newBanNode(t, "frontal")
	const banned, abusive = "203.0.113.40", "203.0.113.41"
	if err := n.srv.bansDB.UpsertBan("manuel", banned, "", "", "admin", nil); err != nil {
		t.Fatal(err)
	}
	n.srv.reloadBanStore()
	n.srv.f2bEngine = edgef2b.New()
	n.srv.f2bEngine.UpdateConfig(edgef2b.Config{Enabled: true, WindowSec: 300, MaxErrors: 3})
	var got []string
	n.srv.f2bEngine.OnBan = func(b edgef2b.Ban) { got = append(got, b.IP) }

	for i := 0; i < 10; i++ {
		n.srv.feedF2B(banned, http.StatusForbidden)
	}
	for i := 0; i < 3; i++ {
		n.srv.feedF2B(abusive, http.StatusForbidden)
	}
	if len(got) != 1 || got[0] != abusive {
		t.Fatalf("seule l'IP non bannie doit déclencher Fail2Ban, bans : %v", got)
	}
}

func TestPeerSyncDoesNotResurrectAnUnbannedIP(t *testing.T) {
	a, b := newBanNode(t, "frontal"), newBanNode(t, "backup")
	const ip = "203.0.113.50"
	if err := a.srv.bansDB.UpsertBan("f2b-a", ip, "", "", "fail2ban", nil); err != nil {
		t.Fatal(err)
	}
	// b a reçu le déban de l'Admin, a non (Admin injoignable pour lui).
	b.srv.applyUnbans([]edgews.UnbanEntry{{IP: ip}})
	b.peerOf(a)
	p, _ := b.srv.peers.LookupByEndpoint(a.http.URL)
	b.srv.syncBansFromPeer(context.Background(), http.DefaultClient, p)
	if b.blocked(ip) {
		t.Fatal("un ban antérieur au déban ne doit pas revenir par un pair")
	}

	// Un ban reposé par le pair après le déban, lui, se propage.
	time.Sleep(1100 * time.Millisecond)
	if err := a.srv.bansDB.UpsertBan("f2b-a2", ip, "", "", "fail2ban", nil); err != nil {
		t.Fatal(err)
	}
	b.srv.syncBansFromPeer(context.Background(), http.DefaultClient, p)
	if !b.blocked(ip) {
		t.Fatal("un nouveau ban après le déban doit être rattrapé")
	}
}
