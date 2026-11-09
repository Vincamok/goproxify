// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/portal"
)

const loginTestMaster = "cle-maitre-passerelle"

func sealedFor(t *testing.T, secret portal.LoginSecret) string {
	t.Helper()
	pub, err := portal.LoginSealPublicKey(loginTestMaster)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := portal.SealLoginSecret(pub, secret)
	if err != nil {
		t.Fatal(err)
	}
	return sealed
}

func createLogin(t *testing.T, h *PortalHandler, body string) PortalLogin {
	t.Helper()
	rr := groupCall(t, h, http.MethodPost, loginsPath, body)
	if rr.Code != http.StatusCreated {
		t.Fatalf("create login: %d %s", rr.Code, rr.Body.String())
	}
	var l PortalLogin
	_ = json.Unmarshal(rr.Body.Bytes(), &l)
	return l
}

func jsonString(s string) string { raw, _ := json.Marshal(s); return string(raw) }

func TestLoginSecretIsOnlyEverStoredAndRelayedSealed(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	sealed := sealedFor(t, portal.LoginSecret{Password: "TopSecret!", PrivateKey: "PRIVKEY"})

	// Sans secret : le login existe mais la passerelle ne le reçoit pas.
	bare := createLogin(t, h, `{"edge_name":"edge-a","username":"deploy","name":"deploy","all_users":true}`)
	if bare.HasSecret || bare.Name != "deploy" || !bare.Enabled {
		t.Fatalf("login sans secret : %+v", bare)
	}
	if got := BuildPortalPayload(db, nil, "edge-a").SharedLogins; len(got) != 0 {
		t.Fatalf("un login sans secret n'est pas poussé : %+v", got)
	}
	pusher.pushed = nil

	l := createLogin(t, h, `{"edge_name":"edge-a","username":"root","name":"root-prod","sealed":`+jsonString(sealed)+`,"has_password":true,"has_private_key":true,"tags":["Ops"]}`)
	if !l.HasSecret || !l.HasPassword || !l.HasPrivateKey {
		t.Fatalf("login scellé : %+v", l)
	}
	if len(pusher.pushed) != 1 {
		t.Fatalf("créer un login pousse la config du portail (%d)", len(pusher.pushed))
	}
	for _, rr := range []string{
		groupCall(t, h, http.MethodGet, loginsPath+"?edge=edge-a", "").Body.String(),
		groupCall(t, h, http.MethodGet, loginsPath+"/"+l.ID, "").Body.String(),
		groupCall(t, h, http.MethodGet, "/api/v1/portal?edge=edge-a", "").Body.String(),
	} {
		if strings.Contains(rr, "TopSecret!") || strings.Contains(rr, "PRIVKEY") || strings.Contains(rr, "epk") || strings.Contains(rr, sealed[:20]) {
			t.Fatalf("ni le secret ni son enveloppe ne sortent de l'API : %s", rr)
		}
	}

	pushed := BuildPortalPayload(db, nil, "edge-a").SharedLogins
	if len(pushed) != 1 || pushed[0].ID != l.ID || pushed[0].Sealed != sealed || pushed[0].Username != "root" || len(pushed[0].Tags) != 1 || pushed[0].Tags[0] != "ops" {
		t.Fatalf("la passerelle reçoit l'enveloppe telle quelle : %+v", pushed)
	}
	// La passerelle, elle, sait l'ouvrir.
	got, err := portal.OpenLoginSecret([]string{loginTestMaster}, pushed[0].Sealed)
	if err != nil || got.Password != "TopSecret!" || got.PrivateKey != "PRIVKEY" {
		t.Fatalf("ouverture côté passerelle : %v %+v", err, got)
	}

	// Un secret en clair est refusé : seule une enveloppe valide passe.
	for name, bad := range map[string]string{
		"mot de passe en clair": `"hunter2"`,
		"json quelconque":       `"{\"password\":\"hunter2\"}"`,
		"enveloppe tronquée":    `"{\"v\":1,\"epk\":\"AAAA\",\"nonce\":\"AAAA\",\"ct\":\"AAAA\"}"`,
	} {
		rr := groupCall(t, h, http.MethodPut, loginsPath+"/"+l.ID, `{"sealed":`+bad+`}`)
		if rr.Code != http.StatusBadRequest || strings.Contains(rr.Body.String(), "hunter2") {
			t.Errorf("%s : %d %s", name, rr.Code, rr.Body.String())
		}
	}
	stored := BuildPortalPayload(db, nil, "edge-a").SharedLogins
	if len(stored) != 1 || stored[0].Sealed != sealed {
		t.Fatal("un refus ne modifie pas le secret en place")
	}
	var plain int
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_logins WHERE secret_sealed LIKE '%TopSecret%'`).Scan(&plain)
	if plain != 0 {
		t.Fatal("aucun secret en clair en base")
	}
}

func TestLoginUpdateKeepsSecretAndResolvesGroupsForThePush(t *testing.T) {
	db, h, _ := destTestEnv(t)
	sealed := sealedFor(t, portal.LoginSecret{Password: "x"})

	g := groupCall(t, h, http.MethodPost, "/api/v1/portal/groups?edge=edge-a", `{"name":"Admins","members":["Alice@Example.fr","bob@example.fr"]}`)
	var grp PortalGroup
	_ = json.Unmarshal(g.Body.Bytes(), &grp)
	if grp.ID == "" {
		t.Fatalf("groupe : %d %s", g.Code, g.Body.String())
	}
	mk := func(name, host string) string {
		rr := groupCall(t, h, http.MethodPost, "/api/v1/portal/destinations", `{"edge_name":"edge-a","kind":"ssh","name":"`+name+`","host":"`+host+`"}`)
		var d PortalDestination
		_ = json.Unmarshal(rr.Body.Bytes(), &d)
		return d.ID
	}
	d1, d2, d3 := mk("web", "10.0.0.1"), mk("db", "10.0.0.2"), mk("cache", "10.0.0.3")
	dg := groupCall(t, h, http.MethodPost, destGroupsPath+"?edge=edge-a", `{"name":"Data","targets":["`+d2+`","`+d3+`"]}`)
	var dgrp PortalDestGroup
	_ = json.Unmarshal(dg.Body.Bytes(), &dgrp)

	l := createLogin(t, h, `{"edge_name":"edge-a","username":"root","name":"root","sealed":`+jsonString(sealed)+`,"groups":["`+grp.ID+`"],"dest_ids":["`+d1+`"],"dest_groups":["`+dgrp.ID+`"]}`)

	pushed := BuildPortalPayload(db, nil, "edge-a").SharedLogins
	if len(pushed) != 1 {
		t.Fatalf("poussés : %+v", pushed)
	}
	p := pushed[0]
	if strings.Join(p.Members, ",") != "alice@example.fr,bob@example.fr" {
		t.Fatalf("les groupes Access sont développés en identités : %v", p.Members)
	}
	if len(p.DestIDs) != 3 {
		t.Fatalf("la destination directe et celles du groupe de destinations : %v", p.DestIDs)
	}
	if p.AllUsers {
		t.Fatal("pas de droit d'usage large par défaut")
	}

	// Modifier sans fournir `sealed` conserve le secret ; fournir une chaîne vide le retire.
	rr := groupCall(t, h, http.MethodPut, loginsPath+"/"+l.ID, `{"name":"root-2","all_users":true,"dest_ids":[]}`)
	if rr.Code != 200 {
		t.Fatalf("update : %d %s", rr.Code, rr.Body.String())
	}
	p = BuildPortalPayload(db, nil, "edge-a").SharedLogins[0]
	if p.Sealed != sealed || p.Name != "root-2" || !p.AllUsers || len(p.DestIDs) != 2 {
		t.Fatalf("après modification : %+v", p)
	}
	rr = groupCall(t, h, http.MethodPut, loginsPath+"/"+l.ID, `{"sealed":""}`)
	var cleared PortalLogin
	_ = json.Unmarshal(rr.Body.Bytes(), &cleared)
	if cleared.HasSecret || len(BuildPortalPayload(db, nil, "edge-a").SharedLogins) != 0 {
		t.Fatalf("retirer le secret retire le login de la poussée : %+v", cleared)
	}

	// Désactivé : jamais poussé, même scellé.
	groupCall(t, h, http.MethodPut, loginsPath+"/"+l.ID, `{"sealed":`+jsonString(sealed)+`,"enabled":false}`)
	if got := BuildPortalPayload(db, nil, "edge-a").SharedLogins; len(got) != 0 {
		t.Fatalf("login désactivé poussé : %+v", got)
	}

	// Supprimer une destination la retire des liaisons directes du login.
	groupCall(t, h, http.MethodPut, loginsPath+"/"+l.ID, `{"enabled":true,"dest_ids":["`+d1+`"],"dest_groups":[]}`)
	groupCall(t, h, http.MethodDelete, "/api/v1/portal/destinations/"+d1, "")
	got := BuildPortalPayload(db, nil, "edge-a").SharedLogins
	if len(got) != 1 || len(got[0].DestIDs) != 0 {
		t.Fatalf("destination supprimée : %+v", got)
	}
}

func TestLoginValidationAndDeleteAndEmptyPushIsNotNull(t *testing.T) {
	db, h, pusher := destTestEnv(t)
	sealed := sealedFor(t, portal.LoginSecret{Password: "x"})
	l := createLogin(t, h, `{"edge_name":"edge-a","username":"root","name":"Root","sealed":`+jsonString(sealed)+`}`)

	for name, tc := range map[string]struct{ method, path, body string }{
		"sans passerelle":    {"POST", loginsPath, `{"username":"x"}`},
		"sans identifiant":   {"POST", loginsPath, `{"edge_name":"edge-a","name":"x"}`},
		"changer de portée":  {"PUT", loginsPath + "/" + l.ID, `{"edge_name":"edge-b"}`},
		"identifiant effacé": {"PUT", loginsPath + "/" + l.ID, `{"username":"  "}`},
	} {
		if rr := groupCall(t, h, tc.method, tc.path, tc.body); rr.Code != http.StatusBadRequest {
			t.Errorf("%s : %d %s", name, rr.Code, rr.Body.String())
		}
	}
	if rr := groupCall(t, h, http.MethodPost, loginsPath, `{"edge_name":"edge-a","username":"x","name":"ROOT"}`); rr.Code != http.StatusConflict {
		t.Errorf("doublon de nom : %d", rr.Code)
	}
	if rr := groupCall(t, h, http.MethodPut, loginsPath+"/absent", `{"name":"x"}`); rr.Code != http.StatusNotFound {
		t.Errorf("login absent : %d", rr.Code)
	}

	pusher.pushed = nil
	if rr := groupCall(t, h, http.MethodDelete, loginsPath+"/"+l.ID, ""); rr.Code != http.StatusNoContent || len(pusher.pushed) != 1 {
		t.Fatalf("delete : %d, poussées=%d", rr.Code, len(pusher.pushed))
	}
	raw, _ := json.Marshal(BuildPortalPayload(db, nil, "edge-a"))
	if !strings.Contains(string(raw), `"shared_logins":[]`) {
		t.Fatalf("la liste poussée est vide mais non nulle (elle retire les logins de la passerelle) : %s", raw)
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_logins`).Scan(&n)
	if n != 0 {
		t.Fatalf("login supprimé : %d", n)
	}
}

func TestLoginPubKeyFallsBackToTheLastKeyWhenNoGatewayAnswers(t *testing.T) {
	db, h, _ := destTestEnv(t)
	if rr := groupCall(t, h, http.MethodGet, loginsPath+"/pubkey", ""); rr.Code != http.StatusBadRequest {
		t.Fatalf("passerelle requise : %d", rr.Code)
	}
	if rr := groupCall(t, h, http.MethodGet, loginsPath+"/pubkey?edge=edge-a", ""); rr.Code != http.StatusBadGateway {
		t.Fatalf("aucune clé connue : %d", rr.Code)
	}
	want, _ := portal.LoginSealPublicKey(loginTestMaster)
	_ = admindb.SetSetting(db, settingLoginPubKeyPrefix+"edge-a", want)
	rr := groupCall(t, h, http.MethodGet, loginsPath+"/pubkey?edge=edge-a", "")
	var out struct {
		PublicKey string `json:"public_key"`
	}
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if rr.Code != 200 || out.PublicKey != want {
		t.Fatalf("clé gardée : %d %s", rr.Code, rr.Body.String())
	}
}
