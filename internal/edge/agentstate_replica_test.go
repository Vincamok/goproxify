// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/config"
	edgeagent "github.com/vincamok/goproxify/internal/edge/agent"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/edge/proxy"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// stateNode est une passerelle de groupe HA qui reçoit les états des Agents et les échange avec ses pairs.
type stateNode struct {
	*haNode
	replicaPosts atomic.Int32 // états reçus d'un pair
	replicaGets  atomic.Int32 // tirages d'un pair qui ont reçu un document
}

func newStateNode(t *testing.T, name, haKey string, members []string) *stateNode {
	t.Helper()
	t.Setenv("GPX_PORTAL_MASTER_KEY", "cle-maitre-"+name)
	cfg := &config.EdgeConfig{}
	cfg.Identity.NodeName = name
	log := edgelog.New("error", "text", "")
	s := &Server{cfg: cfg, log: log, table: &router.Table{}, portal: portal.NewService(log.Logger()), nodeStore: edgeagent.NewNodeStore()}
	if err := s.portal.ApplyConfig(portal.Config{
		Enabled: false, HAStandby: true, HAGroup: "ha-1", HAMembers: members, HAKey: haKey,
		DBPath: filepath.Join(t.TempDir(), name+".gpx"),
	}); err != nil {
		t.Fatal(err)
	}
	n := &stateNode{}
	mux := http.NewServeMux()
	mux.HandleFunc("PUT /internal/v1/agent/state", s.handleAgentState)
	mux.HandleFunc("GET "+agentNodesReplicaPath, s.handleAgentNodesReplicaExport)
	mux.HandleFunc("GET "+agentStateReplicaPath, func(w http.ResponseWriter, r *http.Request) {
		rec := httptest.NewRecorder()
		s.handleAgentStateReplicaExport(rec, r)
		if rec.Code == http.StatusOK {
			n.replicaGets.Add(1)
		}
		for k, v := range rec.Header() {
			w.Header()[k] = v
		}
		w.WriteHeader(rec.Code)
		w.Write(rec.Body.Bytes())
	})
	mux.HandleFunc("POST "+agentStateReplicaPath, func(w http.ResponseWriter, r *http.Request) {
		n.replicaPosts.Add(1)
		s.handleAgentStateReplicaImport(w, r)
	})
	ts := httptest.NewServer(mux)
	t.Cleanup(ts.Close)
	n.haNode = &haNode{name: name, srv: s, http: ts}
	return n
}

func putAgentState(t *testing.T, n *stateNode, st map[string]any) int {
	t.Helper()
	b, _ := json.Marshal(st)
	req, _ := http.NewRequest(http.MethodPut, n.http.URL+"/internal/v1/agent/state", bytes.NewReader(b))
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	return resp.StatusCode
}

func hasHost(n *stateNode, host string) bool {
	_, ok := n.srv.table.ByHost(host)
	return ok
}

const groupKey = "cle-du-groupe"

// Un état reçu par un membre atteint l'autre, retraits compris, et ne revient pas vers lui.
func TestAgentStateIsReplicatedToGroupPeers(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := newStateNode(t, "frontal", groupKey, members), newStateNode(t, "backup", groupKey, members)
	link(a.haNode, b.haNode)

	const x, y = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222"
	if code := putAgentState(t, a, state("portainer", "1", 1,
		portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80"),
		portainerRoute("1", y, "y.example.fr", "http://10.1.0.2:80"))); code != http.StatusOK {
		t.Fatalf("état refusé : %d", code)
	}
	waitFor(t, "les deux routes arrivent sur le pair", func() bool { return hasHost(b, "x.example.fr") && hasHost(b, "y.example.fr") })

	// L'Agent ne déclare plus que x : y disparaît des deux membres.
	if code := putAgentState(t, a, state("portainer", "1", 2, portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80"))); code != http.StatusOK {
		t.Fatalf("état refusé : %d", code)
	}
	waitFor(t, "le retrait se propage", func() bool { return !hasHost(b, "y.example.fr") })
	if !hasHost(a, "x.example.fr") || hasHost(a, "y.example.fr") || !hasHost(b, "x.example.fr") {
		t.Fatal("x reste sur les deux membres, y n'est sur aucun")
	}

	// Un état transmis ne repart pas : A n'a reçu aucun état de B.
	time.Sleep(600 * time.Millisecond)
	if n := a.replicaPosts.Load(); n != 0 {
		t.Fatalf("le frontal a reçu %d état(s) de son pair : un état transmis ne doit pas être renvoyé", n)
	}
}

// Un membre qui revient (table vide) rattrape les états auprès de son pair, sans l'Agent ; le condensé évite de
// retélécharger quand tout est à jour.
func TestAgentStateCatchUpFromPeer(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := newStateNode(t, "frontal", groupKey, members), newStateNode(t, "backup", groupKey, members)
	// Pas de liaison au début : A reçoit l'état pendant que B est absent.
	const x = "xxxxxxxxxxxx1111"
	putAgentState(t, a, state("portainer", "1", 7, portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80")))
	if hasHost(b, "x.example.fr") {
		t.Fatal("B n'a encore rien reçu")
	}

	link(a.haNode, b.haNode)
	peerA := proxy.PeerInfo{Name: "frontal", Endpoint: a.http.URL, Token: "tok"}
	client := &http.Client{Timeout: 3 * time.Second}
	b.srv.syncAgentStateFromPeer(context.Background(), client, peerA)
	if !hasHost(b, "x.example.fr") {
		t.Fatal("B doit retrouver la route auprès de son pair")
	}
	if got := a.replicaGets.Load(); got != 1 {
		t.Fatalf("un document tiré : %d", got)
	}

	b.srv.syncAgentStateFromPeer(context.Background(), client, peerA)
	if got := a.replicaGets.Load(); got != 1 {
		t.Fatalf("mêmes générations : le pair répond 304 sans document, obtenu %d documents", got)
	}
}

// Un état plus ancien que celui que le membre a déjà accepté est ignoré.
func TestAgentStateOlderGenerationFromPeerIsIgnored(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := newStateNode(t, "frontal", groupKey, members), newStateNode(t, "backup", groupKey, members)
	const x, y = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222"
	putAgentState(t, a, state("portainer", "1", 3, portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80")))
	putAgentState(t, b, state("portainer", "1", 9, portainerRoute("1", y, "y.example.fr", "http://10.1.0.2:80")))

	link(a.haNode, b.haNode)
	b.srv.syncAgentStateFromPeer(context.Background(), &http.Client{Timeout: 3 * time.Second},
		proxy.PeerInfo{Name: "frontal", Endpoint: a.http.URL, Token: "tok"})
	if hasHost(b, "x.example.fr") || !hasHost(b, "y.example.fr") {
		t.Fatal("B garde sa génération 9 : l'état 3 de A ne s'applique pas")
	}
	// À l'inverse, A prend la génération 9 de B.
	a.srv.syncAgentStateFromPeer(context.Background(), &http.Client{Timeout: 3 * time.Second},
		proxy.PeerInfo{Name: "backup", Endpoint: b.http.URL, Token: "tok"})
	if hasHost(a, "x.example.fr") || !hasHost(a, "y.example.fr") {
		t.Fatal("A doit adopter l'état plus récent de B et retirer x")
	}
}

// Un pair d'un autre groupe (autre clé) n'est pas cru.
func TestAgentStateFromAnotherGroupIsRejected(t *testing.T) {
	a := newStateNode(t, "frontal", groupKey, []string{"frontal", "backup"})
	c := newStateNode(t, "intrus", "autre-cle", []string{"intrus", "frontal"})
	const x = "xxxxxxxxxxxx1111"
	putAgentState(t, c, state("portainer", "1", 1, portainerRoute("1", x, "x.example.fr", "http://10.9.0.1:80")))

	doc, err := sealAgentStateReplica(agentStateReplica{States: c.srv.agentStates.all()}, "autre-cle")
	if err != nil {
		t.Fatal(err)
	}
	resp, err := http.Post(a.http.URL+agentStateReplicaPath, "application/octet-stream", bytes.NewReader(doc))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest || hasHost(a, "x.example.fr") {
		t.Fatalf("un document chiffré par une autre clé est refusé : status %d", resp.StatusCode)
	}
}

// Un pair qui n'est pas membre du groupe ne reçoit rien.
func TestAgentStateIsNotSentOutsideTheGroup(t *testing.T) {
	a := newStateNode(t, "frontal", groupKey, []string{"frontal"})
	b := newStateNode(t, "voisin", groupKey, []string{"voisin"})
	link(a.haNode, b.haNode)
	const x = "xxxxxxxxxxxx1111"
	putAgentState(t, a, state("portainer", "1", 1, portainerRoute("1", x, "x.example.fr", "http://10.1.0.1:80")))
	time.Sleep(600 * time.Millisecond)
	if hasHost(b, "x.example.fr") || b.replicaPosts.Load() != 0 {
		t.Fatal("un pair hors du groupe ne doit rien recevoir")
	}
}

// Un Agent renvoie son état complet à chaque scan avec une génération plus récente, même quand rien n'a changé : seul un
// changement de contenu est transmis aux pairs ; les générations avancent quand même, et les condensés restent égaux.
func TestAgentStateUnchangedContentIsNotReplicatedAgain(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := newStateNode(t, "frontal", groupKey, members), newStateNode(t, "backup", groupKey, members)
	link(a.haNode, b.haNode)
	const x, y = "xxxxxxxxxxxx1111", "yyyyyyyyyyyy2222"
	route := func(cid, host string) map[string]any { return portainerRoute("1", cid, host, "http://10.1.0.1:80") }

	putAgentState(t, a, state("portainer", "1", 1, route(x, "x.example.fr")))
	waitFor(t, "premier état reçu par le pair", func() bool { return b.replicaPosts.Load() == 1 })

	// Même contenu, générations plus récentes, routes dans un autre ordre : rien ne repart.
	putAgentState(t, a, state("portainer", "1", 2, route(x, "x.example.fr")))
	putAgentState(t, a, state("portainer", "1", 3, route(x, "x.example.fr")))
	time.Sleep(700 * time.Millisecond)
	if got := b.replicaPosts.Load(); got != 1 {
		t.Fatalf("un état identique ne doit pas être retransmis : %d envois", got)
	}
	if a.srv.agentStates.digest() != b.srv.agentStates.digest() {
		t.Fatal("même contenu des deux côtés : mêmes condensés, malgré des générations différentes")
	}

	// Un contenu qui change repart.
	putAgentState(t, a, state("portainer", "1", 4, route(x, "x.example.fr"), route(y, "y.example.fr")))
	waitFor(t, "l'état modifié atteint le pair", func() bool { return b.replicaPosts.Load() == 2 && hasHost(b, "y.example.fr") })
}

func TestAgentStateStorePutReportsChanges(t *testing.T) {
	var s agentStateStore
	mk := func(gen int64, hosts ...string) *agentStatePayload {
		st := &agentStatePayload{AgentName: "ag", Source: "portainer", Scope: "1", Generation: gen}
		for _, h := range hosts {
			st.Routes = append(st.Routes, agentContainerPayload{ID: "portainer:1:" + h, Host: h})
		}
		return st
	}
	if !s.put(mk(1, "a", "b")) {
		t.Fatal("premier état : changement")
	}
	if s.put(mk(2, "b", "a")) {
		t.Fatal("mêmes routes dans un autre ordre : pas de changement")
	}
	if s.put(mk(1, "c")) {
		t.Fatal("une génération plus ancienne est ignorée")
	}
	if !s.put(mk(3, "a")) {
		t.Fatal("une route en moins : changement")
	}
	if st, _ := s.get("ag|portainer|1"); st.Generation != 3 {
		t.Fatalf("génération retenue : %d", st.Generation)
	}
}
