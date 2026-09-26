// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/proxy"
)

// haNode est une passerelle minimale : un service portail en attente et ses endpoints de réplication.
type haNode struct {
	name string
	srv  *Server
	http *httptest.Server
}

func newHANode(t *testing.T, name, haKey string, shared bool, members []string) *haNode {
	t.Helper()
	t.Setenv("GPX_PORTAL_MASTER_KEY", "cle-maitre-"+name)
	cfg := &config.EdgeConfig{}
	cfg.Identity.NodeName = name
	log := edgelog.New("error", "text", "")
	s := &Server{cfg: cfg, log: log, portal: portal.NewService(log.Logger()), portalRepl: &portalReplicator{}}
	s.portal.SetStoreChangeHook(s.schedulePortalReplicaPush)
	err := s.portal.ApplyConfig(portal.Config{
		Enabled: false, HAStandby: true, HAGroup: "ha-1", HAMembers: members, HAKey: haKey, HASharedSess: shared,
		DBPath: filepath.Join(t.TempDir(), name+".gpx"),
	})
	if err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET "+portalReplicaPath, s.handlePortalReplicaExport)
	mux.HandleFunc("POST "+portalReplicaPath, s.handlePortalReplicaImport)
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	return &haNode{name: name, srv: s, http: ts}
}

func link(a, b *haNode) {
	a.srv.peers = proxy.NewPeerRegistry()
	a.srv.peers.Replace([]proxy.PeerInfo{{Name: b.name, Endpoint: b.http.URL, Token: "tok-" + b.name}})
	b.srv.peers = proxy.NewPeerRegistry()
	b.srv.peers.Replace([]proxy.PeerInfo{{Name: a.name, Endpoint: a.http.URL, Token: "tok-" + a.name}})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

func TestPortalReplicaIsPushedImmediatelyToGroupPeers(t *testing.T) {
	members := []string{"frontal", "backup"}
	a := newHANode(t, "frontal", "cle-du-groupe", true, members)
	b := newHANode(t, "backup", "cle-du-groupe", true, members)
	link(a, b)
	storeA, _, _, _, _ := a.srv.portal.ReplicaInfo()
	storeB, _, _, _, _ := b.srv.portal.ReplicaInfo()

	// écriture locale sur frontal : envoi automatique (debounce) vers backup
	if err := storeA.CreateUser(portal.UserRecord{ID: "u1", Username: "alice@example.fr", PasswordHash: "h"}); err != nil {
		t.Fatal(err)
	}
	_ = storeA.PutAuthSession("tok-web", portal.AuthSession{UserID: "u1", Username: "alice", VaultKey: "aa", Expires: time.Now().Add(time.Hour)})
	waitFor(t, "le compte et la session atteignent backup", func() bool {
		_, okU := storeB.FindUserByID("u1")
		_, okS := storeB.GetAuthSession("tok-web")
		return okU && okS
	})

	// et dans l'autre sens
	_ = storeB.SetVaultBlob("u1", []byte("coffre"))
	waitFor(t, "le coffre revient sur frontal", func() bool { return string(storeA.VaultBlob("u1")) == "coffre" })
}

func TestPortalReplicaIsPulledFromPeers(t *testing.T) {
	members := []string{"frontal", "backup"}
	a := newHANode(t, "frontal", "cle-du-groupe", false, members)
	b := newHANode(t, "backup", "cle-du-groupe", false, members)
	link(a, b)
	storeA, _, _, _, _ := a.srv.portal.ReplicaInfo()
	storeB, _, _, _, _ := b.srv.portal.ReplicaInfo()
	// on coupe l'envoi immédiat pour ne tester que le tirage périodique
	a.srv.portalRepl = nil
	_ = storeA.CreateUser(portal.UserRecord{ID: "u2", Username: "bob@example.fr", PasswordHash: "h2"})

	p, _ := b.srv.peers.LookupByEndpoint(a.http.URL)
	b.srv.syncPortalReplicaFromPeer(context.Background(), http.DefaultClient, p)
	if u, ok := storeB.FindUserByID("u2"); !ok || u.PasswordHash != "h2" {
		t.Fatalf("le tirage doit récupérer le compte de frontal: %+v %v", u, ok)
	}
}

func TestPortalReplicaStickyKeepsSessionsLocal(t *testing.T) {
	members := []string{"frontal", "backup"}
	a := newHANode(t, "frontal", "cle-du-groupe", false, members) // sticky
	b := newHANode(t, "backup", "cle-du-groupe", false, members)
	link(a, b)
	storeA, _, _, _, _ := a.srv.portal.ReplicaInfo()
	storeB, _, _, _, _ := b.srv.portal.ReplicaInfo()
	_ = storeA.CreateUser(portal.UserRecord{ID: "u1", Username: "alice@example.fr", PasswordHash: "h"})
	_ = storeA.PutAuthSession("tok-web", portal.AuthSession{UserID: "u1", Expires: time.Now().Add(time.Hour)})
	waitFor(t, "le compte atteint backup", func() bool { _, ok := storeB.FindUserByID("u1"); return ok })
	time.Sleep(400 * time.Millisecond)
	if _, ok := storeB.GetAuthSession("tok-web"); ok {
		t.Fatal("mode sticky : la session web ne doit pas être répliquée")
	}
}

func TestPortalReplicaRejectsAnotherGroupKeyAndIgnoresNonMembers(t *testing.T) {
	members := []string{"frontal", "backup"}
	a := newHANode(t, "frontal", "cle-du-groupe", false, members)
	b := newHANode(t, "backup", "AUTRE-CLE", false, members)
	link(a, b)
	storeA, _, _, _, _ := a.srv.portal.ReplicaInfo()
	storeB, _, _, _, _ := b.srv.portal.ReplicaInfo()
	_ = storeA.CreateUser(portal.UserRecord{ID: "u1", Username: "alice@example.fr", PasswordHash: "h"})
	time.Sleep(500 * time.Millisecond)
	if _, ok := storeB.FindUserByID("u1"); ok {
		t.Fatal("une clé de groupe différente ne doit rien déchiffrer")
	}

	// un pair qui n'est pas membre du groupe n'est jamais sollicité
	c := newHANode(t, "autre", "cle-du-groupe", false, []string{"frontal", "backup"})
	a.srv.peers = proxy.NewPeerRegistry()
	a.srv.peers.Replace([]proxy.PeerInfo{{Name: "intrus", Endpoint: c.http.URL, Token: "t"}})
	if peers := a.srv.haPortalPeers(members); len(peers) != 0 {
		t.Fatalf("un pair hors groupe ne doit pas recevoir l'état: %+v", peers)
	}
}

func TestPortalReplicaEndpointsAreInertOutsideAGroup(t *testing.T) {
	log := edgelog.New("error", "text", "")
	s := &Server{cfg: &config.EdgeConfig{}, log: log, portal: portal.NewService(log.Logger())}
	rec := httptest.NewRecorder()
	s.handlePortalReplicaExport(rec, httptest.NewRequest(http.MethodGet, portalReplicaPath, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("hors groupe: %d", rec.Code)
	}
	rec = httptest.NewRecorder()
	s.handlePortalReplicaImport(rec, httptest.NewRequest(http.MethodPost, portalReplicaPath, nil))
	if rec.Code != http.StatusNoContent {
		t.Fatalf("hors groupe: %d", rec.Code)
	}
}
