// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

func card(version int64, group string, domains ...string) edgews.GroupCard {
	c := edgews.GroupCard{Group: group, Version: version, Members: []edgews.CardMember{
		{ID: "n1", Name: "frontal", Endpoint: "https://a:8443"}, {ID: "n2", Name: "backup", Endpoint: "https://b:8443"},
	}}
	for _, d := range domains {
		c.Domains = append(c.Domains, edgews.CardDomain{ID: "d-" + d, Domain: d, EdgeID: "n1", DNSProvider: "ovh", DNSCredentials: `{"k":"secret"}`, CertMethod: "dns"})
	}
	return c
}

// Une fiche poussée à un seul membre arrive chez l'autre, qui la sert à un Admin qui se reconstitue.
func TestGroupCardReachesTheOtherMember(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	link(a.haNode, b.haNode)
	adminPush(t, a, edgews.TypePushGroupCard, card(3, "ha-1", "app.example.fr"))

	pullPushed(t, a, b)
	got, ok := b.srv.groupCard.get()
	if !ok || got.Version != 3 || len(got.Domains) != 1 || got.Domains[0].DNSCredentials != `{"k":"secret"}` {
		t.Fatalf("B doit détenir la fiche v3 de A : %+v", got)
	}

	rec := httptest.NewRecorder()
	b.srv.handleGroupCard(rec, httptest.NewRequest(http.MethodGet, groupCardPath, nil))
	var served edgews.GroupCard
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &served) != nil || served.Version != 3 || len(served.Members) != 2 {
		t.Fatalf("la fiche est servie : %d %s", rec.Code, rec.Body.String())
	}
}

// Une fiche plus ancienne ne remplace pas la nôtre, qu'elle vienne de l'Admin ou d'un pair dont la date de réception est
// plus récente.
func TestGroupCardOlderVersionNeverWins(t *testing.T) {
	members := []string{"frontal", "backup"}
	a, b := pushedNode(t, "frontal", members), pushedNode(t, "backup", members)
	link(a.haNode, b.haNode)
	adminPush(t, b, edgews.TypePushGroupCard, card(5, "ha-1"))
	time.Sleep(5 * time.Millisecond)
	adminPush(t, a, edgews.TypePushGroupCard, card(4, "ha-1", "vieux.example.fr")) // reçue plus tard, mais plus ancienne

	pullPushed(t, a, b)
	if got, _ := b.srv.groupCard.get(); got.Version != 5 || len(got.Domains) != 0 {
		t.Fatalf("B garde la v5 : %+v", got)
	}
	pullPushed(t, b, a)
	if got, _ := a.srv.groupCard.get(); got.Version != 5 {
		t.Fatalf("A passe à la v5 : %+v", got)
	}

	err := b.srv.handleWSAdminMessage("admin", edgews.Message{Type: edgews.TypePushGroupCard, Payload: mustJSON(t, card(2, "ha-1"))})
	if err == nil {
		t.Fatal("une fiche plus ancienne poussée par l'Admin est refusée")
	}
	if got, _ := b.srv.groupCard.get(); got.Version != 5 {
		t.Fatalf("la v5 reste : %+v", got)
	}
}

// La même version répétée (l'Admin la renvoie à chaque connexion) ne fait rien, et sans nom de groupe la fiche est refusée.
func TestGroupCardSameVersionAndInvalid(t *testing.T) {
	a := pushedNode(t, "frontal", []string{"frontal", "backup"})
	adminPush(t, a, edgews.TypePushGroupCard, card(1, "ha-1"))
	adminPush(t, a, edgews.TypePushGroupCard, card(1, "ha-1"))
	if err := a.srv.handleWSAdminMessage("admin", edgews.Message{Type: edgews.TypePushGroupCard, Payload: mustJSON(t, card(9, ""))}); err == nil {
		t.Fatal("une fiche sans groupe est refusée")
	}
	if got, _ := a.srv.groupCard.get(); got.Version != 1 {
		t.Fatalf("la v1 reste : %+v", got)
	}
}

// Un membre qui redémarre pendant la coupure de l'Admin retrouve sa fiche.
func TestGroupCardSurvivesARestart(t *testing.T) {
	t.Setenv("GPX_GROUP_CARD_PATH", t.TempDir()+"/group-card.gpx")
	a := pushedNode(t, "frontal", []string{"frontal", "backup"})
	adminPush(t, a, edgews.TypePushGroupCard, card(7, "ha-1", "app.example.fr"))

	restarted := &Server{cfg: a.srv.cfg, log: a.srv.log, cache: a.srv.cache}
	restarted.loadGroupCardFromDisk()
	if got, ok := restarted.groupCard.get(); !ok || got.Version != 7 || len(got.Domains) != 1 {
		t.Fatalf("fiche relue : %+v", got)
	}
}

func TestGroupCardNotFoundBeforeTheAdminPushedOne(t *testing.T) {
	s := &Server{}
	rec := httptest.NewRecorder()
	s.handleGroupCard(rec, httptest.NewRequest(http.MethodGet, groupCardPath, nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("404 attendu, %d", rec.Code)
	}
}

func mustJSON(t *testing.T, v any) json.RawMessage {
	t.Helper()
	b, err := json.Marshal(v)
	if err != nil {
		t.Fatal(err)
	}
	return b
}
