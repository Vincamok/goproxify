// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

// proxyNode ajoute à un membre de groupe HA ce qu'il faut pour porter des proxys configurés.
func proxyNode(t *testing.T, name string, members []string) *stateNode {
	t.Helper()
	n := newStateNode(t, name, groupKey, members)
	s := n.srv
	s.certStore = edgetls.NewCertStore()
	s.snippetStore = router.NewSnippetStore()
	s.providerStore = router.NewAuthProviderStore()
	s.ech = edgetls.NewECHManager()
	s.cache = edgecache.New(filepath.Join(t.TempDir(), "edge-cache.gpx"), "cle-passerelle")
	s.proxyStore = proxystore.New(t.TempDir())
	if err := s.proxyStore.EnsureDirs(); err != nil {
		t.Fatal(err)
	}
	n.http.Config.Handler.(*http.ServeMux).HandleFunc("GET "+proxyReplicaPath, s.handleProxyReplicaExport)
	return n
}

func publishProxy(t *testing.T, n *stateNode, id, host, backend string, at time.Time) {
	t.Helper()
	cfg, _ := json.Marshal(router.Route{ID: id, Host: host, Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend}}})
	env := &proxystore.Envelope{ID: id, Host: host, Enabled: true, Config: cfg, UpdatedAt: at}
	if err := n.srv.proxyStore.WriteProd(env); err != nil {
		t.Fatal(err)
	}
	if err := n.srv.ApplyFileProxy(env); err != nil {
		t.Fatal(err)
	}
}

func pullProxies(t *testing.T, from, to *stateNode) {
	t.Helper()
	to.srv.syncProxiesFromPeer(context.Background(), &http.Client{Timeout: 3 * time.Second},
		proxy.PeerInfo{Name: from.name, Endpoint: from.http.URL, Token: "tok"})
}

func backendOf(n *stateNode, host string) string {
	rt, ok := n.srv.table.ByHost(host)
	if !ok || len(rt.Backends) == 0 {
		return ""
	}
	return rt.Backends[0].URL
}

// Un proxy publié sur un seul membre (l'autre était absent) arrive chez l'autre, qui le sert.
func TestProxyReplicaCatchesUpAMemberThatMissedAPublish(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := proxyNode(t, "frontal", members), proxyNode(t, "backup", members)
	link(a.haNode, b.haNode)
	publishProxy(t, a, "p1", "app.example.fr", "http://10.0.0.1:80", time.Now().UTC())

	pullProxies(t, a, b)
	if backendOf(b, "app.example.fr") != "http://10.0.0.1:80" {
		t.Fatal("B doit servir le proxy publié sur A")
	}
	if _, err := b.srv.proxyStore.ReadProdByID("p1"); err != nil {
		t.Fatalf("le proxy est écrit sur le disque de B : %v", err)
	}
}

// La version la plus récente l'emporte, dans les deux sens.
func TestProxyReplicaNewestVersionWins(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := proxyNode(t, "frontal", members), proxyNode(t, "backup", members)
	link(a.haNode, b.haNode)
	now := time.Now().UTC()
	publishProxy(t, a, "p1", "app.example.fr", "http://old:80", now.Add(-time.Hour))
	publishProxy(t, b, "p1", "app.example.fr", "http://new:80", now)

	pullProxies(t, b, a)
	if backendOf(a, "app.example.fr") != "http://new:80" {
		t.Fatalf("A adopte la version plus récente de B : %q", backendOf(a, "app.example.fr"))
	}
	pullProxies(t, a, b)
	if backendOf(b, "app.example.fr") != "http://new:80" {
		t.Fatal("B garde sa version, plus récente que l'ancienne de A")
	}
}

// Un proxy supprimé pendant l'absence d'un membre est supprimé chez lui à son retour ; un proxy recréé ensuite revient.
func TestProxyReplicaPropagatesDeletionsAndRecreation(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := proxyNode(t, "frontal", members), proxyNode(t, "backup", members)
	link(a.haNode, b.haNode)
	now := time.Now().UTC()
	publishProxy(t, a, "p1", "app.example.fr", "http://10.0.0.1:80", now.Add(-time.Hour))
	publishProxy(t, b, "p1", "app.example.fr", "http://10.0.0.1:80", now.Add(-time.Hour))

	// A supprime pendant que B est absent.
	if err := a.srv.removeFileProxy("p1", now); err != nil {
		t.Fatal(err)
	}
	if backendOf(a, "app.example.fr") != "" {
		t.Fatal("A ne sert plus le proxy")
	}
	pullProxies(t, a, b)
	if backendOf(b, "app.example.fr") != "" {
		t.Fatal("B doit supprimer le proxy à son retour")
	}
	if _, err := b.srv.proxyStore.ReadProdByID("p1"); err == nil {
		t.Fatal("le fichier est supprimé sur B")
	}

	// Recréé plus tard sur B avec le même identifiant : il revient chez A.
	publishProxy(t, b, "p1", "app.example.fr", "http://recree:80", now.Add(time.Minute))
	pullProxies(t, b, a)
	if backendOf(a, "app.example.fr") != "http://recree:80" {
		t.Fatalf("un proxy recréé après sa suppression revient : %q", backendOf(a, "app.example.fr"))
	}
}

// Une suppression plus ancienne que la version d'un membre ne l'efface pas.
func TestProxyReplicaOlderDeletionDoesNotEraseNewerVersion(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := proxyNode(t, "frontal", members), proxyNode(t, "backup", members)
	link(a.haNode, b.haNode)
	now := time.Now().UTC()
	publishProxy(t, b, "p1", "app.example.fr", "http://b:80", now)
	if err := a.srv.proxyStore.RecordTombstone("p1", now.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	pullProxies(t, a, b)
	if backendOf(b, "app.example.fr") != "http://b:80" {
		t.Fatal("la version de B est plus récente que la suppression : elle reste")
	}
}

// Une suppression retenue depuis plus de 30 jours est oubliée.
func TestTombstonesExpire(t *testing.T) {
	st := proxystore.New(t.TempDir())
	if err := st.RecordTombstone("vieux", time.Now().Add(-proxystore.TombstoneRetention-time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := st.RecordTombstone("recent", time.Now().Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	got := st.Tombstones()
	if _, ok := got["vieux"]; ok || len(got) != 1 {
		t.Fatalf("seule la suppression récente est retenue : %v", got)
	}
}

// Les mêmes versions des deux côtés : le pair répond 304, rien n'est retéléchargé.
func TestProxyReplicaDigestAvoidsTheDownload(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := proxyNode(t, "frontal", members), proxyNode(t, "backup", members)
	link(a.haNode, b.haNode)
	publishProxy(t, a, "p1", "app.example.fr", "http://10.0.0.1:80", time.Now().UTC())
	pullProxies(t, a, b)

	req, _ := http.NewRequest(http.MethodGet, a.http.URL+proxyReplicaPath, nil)
	req.Header.Set("If-None-Match", `"`+b.srv.proxyReplicaDoc().digest()+`"`)
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotModified {
		t.Fatalf("mêmes versions : %d, attendu 304", resp.StatusCode)
	}
}

// Un proxy qui ne passe pas l'analyse de la route n'entre pas.
func TestProxyReplicaRefusesAnUnparsableProxy(t *testing.T) {
	a := proxyNode(t, "frontal", []string{"frontal", "backup"})
	bad := &proxystore.Envelope{SchemaVersion: 1, ID: "p-bad", Host: "bad.example.fr", Enabled: true, Status: proxystore.StatusProduction,
		Config: json.RawMessage(`{"backends": "pas-une-liste"}`), UpdatedAt: time.Now().UTC()}
	if got := a.srv.mergeProxyReplica(proxyReplica{Proxies: []*proxystore.Envelope{bad}}, "pair"); got != 0 {
		t.Fatalf("un proxy illisible n'est pas adopté : %d", got)
	}
	if _, err := a.srv.proxyStore.ReadProdByID("p-bad"); err == nil {
		t.Fatal("rien n'est écrit")
	}
}
