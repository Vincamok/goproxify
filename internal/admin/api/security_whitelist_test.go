// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type wlEntry struct {
	Value        string `json:"value"`
	Comment      string `json:"comment"`
	BansExempted int    `json:"bans_exempted"`
}

func wlList(t *testing.T, h http.Handler) []wlEntry {
	t.Helper()
	rec := banRequest(h, http.MethodGet, "/api/v1/security/bans/whitelist", "", "198.51.100.9:1")
	if rec.Code != http.StatusOK {
		t.Fatalf("liste : %d %s", rec.Code, rec.Body)
	}
	var out []wlEntry
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	return out
}

func wlAdd(h http.Handler, body string) (int, map[string]any) {
	rec := banRequest(h, http.MethodPost, "/api/v1/security/bans/whitelist", body, "198.51.100.9:1")
	var res map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

func profileCIDRs(t *testing.T, db *sql.DB) (cidrs []string, mode string, exists bool) {
	t.Helper()
	var raw string
	err := db.QueryRow(`SELECT mode, cidrs FROM ip_profiles WHERE id=?`, router.WhitelistProfileID).Scan(&mode, &raw)
	if err == sql.ErrNoRows {
		return nil, "", false
	}
	if err != nil {
		t.Fatal(err)
	}
	_ = json.Unmarshal([]byte(raw), &cidrs)
	return cidrs, mode, true
}

// L'entrée est validée, normalisée, commentée, et recopiée dans un profil allow que les passerelles reçoivent.
func TestWhitelistAddListRemove(t *testing.T) {
	db := openBansDB(t)
	var pushes atomic.Int32
	h := &api.SecurityHandler{DB: db, OnWhitelistChange: func() { pushes.Add(1) }}

	if got := wlList(t, h); len(got) != 0 {
		t.Fatalf("liste initiale : %+v", got)
	}
	if _, _, ok := profileCIDRs(t, db); ok {
		t.Fatal("aucun profil tant que la liste est vide")
	}

	code, res := wlAdd(h, `{"ip":"203.0.113.7/24","comment":"bureau Paris"}`)
	if code != http.StatusCreated || res["added"] != true {
		t.Fatalf("ajout : %d %v", code, res)
	}
	if code, _ := wlAdd(h, `{"ip":"2001:DB8:1::9"}`); code != http.StatusCreated {
		t.Fatalf("ajout IPv6 : %d", code)
	}
	list := wlList(t, h)
	if len(list) != 2 || list[0].Value != "2001:db8:1::9" || list[1].Value != "203.0.113.0/24" || list[1].Comment != "bureau Paris" {
		t.Fatalf("liste après ajouts : %+v", list)
	}
	cidrs, mode, ok := profileCIDRs(t, db)
	if !ok || mode != "allow" || len(cidrs) != 2 {
		t.Fatalf("profil : ok=%v mode=%q cidrs=%v", ok, mode, cidrs)
	}
	if pushes.Load() != 2 {
		t.Fatalf("poussées vers les passerelles : %d, attendu 2", pushes.Load())
	}

	rec := banRequest(h, http.MethodDelete, "/api/v1/security/bans/whitelist?ip="+url.QueryEscape("203.0.113.0/24"), "", "198.51.100.9:1")
	if rec.Code != http.StatusNoContent {
		t.Fatalf("retrait : %d %s", rec.Code, rec.Body)
	}
	if cidrs, _, _ := profileCIDRs(t, db); len(cidrs) != 1 || cidrs[0] != "2001:db8:1::9" {
		t.Fatalf("profil après retrait : %v", cidrs)
	}
	if rec := banRequest(h, http.MethodDelete, "/api/v1/security/bans/whitelist?ip="+url.QueryEscape("203.0.113.0/24"), "", "198.51.100.9:1"); rec.Code != http.StatusNotFound {
		t.Fatalf("retrait d'une entrée absente : %d", rec.Code)
	}
	banRequest(h, http.MethodDelete, "/api/v1/security/bans/whitelist?ip=2001:db8:1::9", "", "198.51.100.9:1")
	if _, _, ok := profileCIDRs(t, db); ok {
		t.Fatal("le profil doit disparaître avec la dernière entrée")
	}
}

func TestWhitelistRejectsInvalidAndTooBroad(t *testing.T) {
	h := &api.SecurityHandler{DB: openBansDB(t)}
	for _, ip := range []string{"", "pas-une-ip", "10.0.0.0/8", "0.0.0.0/0", "203.0.113.256"} {
		if code, _ := wlAdd(h, `{"ip":"`+ip+`"}`); code != http.StatusBadRequest {
			t.Errorf("%q : %d, attendu 400", ip, code)
		}
	}
}

// Une entrée déjà couverte ne change rien ; une entrée plus large absorbe les plus précises.
func TestWhitelistCoveringAndAbsorbing(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	wlAdd(h, `{"ip":"203.0.113.0/25"}`)
	wlAdd(h, `{"ip":"203.0.113.200"}`)

	code, res := wlAdd(h, `{"ip":"203.0.113.9"}`)
	if code != http.StatusOK || res["added"] != false || res["covered_by"] != "203.0.113.0/25" {
		t.Fatalf("adresse déjà couverte : %d %v", code, res)
	}
	if code, _ := wlAdd(h, `{"ip":"203.0.113.0/24"}`); code != http.StatusCreated {
		t.Fatal("ajout de la plage large")
	}
	if got := wlList(t, h); len(got) != 1 || got[0].Value != "203.0.113.0/24" {
		t.Fatalf("la plage large doit absorber les entrées plus précises : %+v", got)
	}
}

// Un ban dont la cible est entièrement exemptée est refusé ; une plage qui ne fait que recouper reste permise.
func TestCreateBanRefusedWhenWhitelisted(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	wlAdd(h, `{"ip":"203.0.113.0/24","comment":"partenaire"}`)

	for _, ip := range []string{"203.0.113.5", "203.0.113.64/26", "203.0.113.0/24"} {
		rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"`+ip+`"}`, "198.51.100.9:1")
		if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "liste blanche") {
			t.Errorf("%s : %d %q, attendu 409 liste blanche", ip, rec.Code, rec.Body)
		}
	}
	if rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"198.51.0.0/16"}`, "192.0.2.1:1"); rec.Code != http.StatusCreated {
		t.Errorf("plage hors liste blanche : %d", rec.Code)
	}
	if rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.0.0/16"}`, "198.51.100.9:1"); rec.Code != http.StatusCreated {
		t.Errorf("plage qui recoupe seulement : %d %s", rec.Code, rec.Body)
	}
}

// Les bans déjà posés sont marqués « exempté » et comptés par l'entrée, sans être supprimés.
func TestWhitelistMarksExistingBansExempt(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	for _, q := range []string{
		`INSERT INTO security_bans (id, ip, source) VALUES ('a', '203.0.113.5', 'fail2ban')`,
		`INSERT INTO security_bans (id, ip, source) VALUES ('b', '203.0.113.64/26', 'native')`,
		`INSERT INTO security_bans (id, ip, source) VALUES ('c', '198.51.100.7', 'threat')`,
		`INSERT INTO security_bans (id, ip, source) VALUES ('d', '203.0.0.0/16', 'native')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	_, res := wlAdd(h, `{"ip":"203.0.113.0/24"}`)
	entry, _ := res["entry"].(map[string]any)
	if entry["bans_exempted"] != float64(2) {
		t.Fatalf("bans neutralisés : %v, attendu 2 (le /16 déborde de l'entrée)", entry["bans_exempted"])
	}
	if got := wlList(t, h); got[0].BansExempted != 2 {
		t.Fatalf("compteur de la liste : %+v", got)
	}

	rec := banRequest(h, http.MethodGet, "/api/v1/security/bans", "", "198.51.100.9:1")
	var bans []struct {
		ID     string `json:"id"`
		Exempt bool   `json:"exempt"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &bans); err != nil {
		t.Fatal(err)
	}
	exempt := map[string]bool{}
	for _, b := range bans {
		exempt[b.ID] = b.Exempt
	}
	if !exempt["a"] || !exempt["b"] || exempt["c"] || exempt["d"] || len(bans) != 4 {
		t.Fatalf("bans exemptés : %v (4 bans attendus, a et b seuls exemptés)", exempt)
	}
}

// Le profil est géré depuis la page Bans : la page Profils IP ne peut ni le modifier ni le supprimer.
func TestManagedProfileCannotBeEditedOrDeleted(t *testing.T) {
	db := openBansDB(t)
	sec := &api.SecurityHandler{DB: db}
	wlAdd(sec, `{"ip":"203.0.113.0/24"}`)
	prof := &api.IPProfilesHandler{DB: db}
	for method, body := range map[string]string{http.MethodPut: `{"name":"x","mode":"deny","cidrs":["8.8.8.8"]}`, http.MethodDelete: ""} {
		rec := banRequest(prof, method, "/api/v1/ip-profiles/"+router.WhitelistProfileID, body, "198.51.100.9:1")
		if rec.Code != http.StatusConflict {
			t.Errorf("%s : %d, attendu 409", method, rec.Code)
		}
	}
	if cidrs, mode, ok := profileCIDRs(t, db); !ok || mode != "allow" || len(cidrs) != 1 {
		t.Fatalf("profil altéré : %v %q %v", cidrs, mode, ok)
	}
}

func TestBanPreviewReportsWhitelist(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	wlAdd(h, `{"ip":"203.0.113.0/25","comment":"bureau"}`)

	res, _ := getPreview(t, h, "ip=203.0.113.9", "198.51.100.9:1")
	if !hasWarning(res, "entièrement en liste blanche (203.0.113.0/25)") {
		t.Errorf("adresse exemptée : %v", res.Warnings)
	}
	res, _ = getPreview(t, h, "ip=203.0.113.0/24", "198.51.100.9:1")
	if !hasWarning(res, "1 entrée(s) de la liste blanche recoupent la cible") {
		t.Errorf("plage qui recoupe : %v", res.Warnings)
	}
	for _, p := range res.Profiles {
		if p.Mode == "allow" {
			t.Errorf("le profil de la liste blanche ne doit pas être doublé dans les profils : %+v", res.Profiles)
		}
	}
	res, _ = getPreview(t, h, "ip=198.51.100.0/24", "198.51.100.77:1")
	if hasWarning(res, "liste blanche") {
		t.Errorf("cible étrangère à la liste blanche : %v", res.Warnings)
	}
}
