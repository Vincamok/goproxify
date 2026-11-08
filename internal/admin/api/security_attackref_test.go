// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/attackref"
)

func attackRefHandler(t *testing.T) (*api.SecurityHandler, *attackref.Miner) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+t.Name()+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	db.SetMaxOpenConns(1)
	t.Cleanup(func() { db.Close() })
	if _, err := db.Exec(`CREATE TABLE security_ban_history (id INTEGER PRIMARY KEY AUTOINCREMENT, ip TEXT, action TEXT, reason TEXT DEFAULT '', source TEXT DEFAULT '', user_agent TEXT DEFAULT '', signals TEXT DEFAULT '', created_at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	if err := attackref.Migrate(db); err != nil {
		t.Fatal(err)
	}
	m := &attackref.Miner{Store: &attackref.Store{DB: db}, Cfg: attackref.DefaultConfig()}
	return &api.SecurityHandler{DB: db, AttackRef: m}, m
}

func arGet(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestAttackRefUnavailableWithoutMiner(t *testing.T) {
	h := &api.SecurityHandler{}
	if rec := arGet(h, "GET", "/api/v1/security/attack-ref/summary", ""); rec.Code != http.StatusServiceUnavailable {
		t.Errorf("sans mineur : %d", rec.Code)
	}
}

func TestAttackRefDossiersAndSummary(t *testing.T) {
	h, m := attackRefHandler(t)
	d := attackref.BuildDossier(attackref.BanInfo{IP: "203.0.113.5", At: time.Now().Add(-48 * time.Hour), Source: "fail2ban"},
		[]attackref.Line{{Ts: time.Now().Add(-49 * time.Hour), Method: "GET", Path: "/.env", Status: 404}})
	if err := m.Store.SaveDossier(t.Context(), d); err != nil {
		t.Fatal(err)
	}
	rec := arGet(h, "GET", "/api/v1/security/attack-ref/dossiers?ip=203.0.113.5", "")
	var res struct {
		Dossiers []attackref.Dossier `json:"dossiers"`
		Total    int                 `json:"total"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &res) != nil || res.Total != 1 || res.Dossiers[0].Paths[0].Template != "/.env" {
		t.Fatalf("dossiers : %d %s", rec.Code, rec.Body)
	}
	if rec := arGet(h, "GET", "/api/v1/security/attack-ref/dossiers?ip=pas-une-ip", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("IP invalide : %d", rec.Code)
	}
	rec = arGet(h, "GET", "/api/v1/security/attack-ref/summary", "")
	var sum struct {
		Summary attackref.Summary `json:"summary"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &sum) != nil || sum.Summary.Dossiers != 1 {
		t.Fatalf("synthèse : %d %s", rec.Code, rec.Body)
	}
}

func TestAttackRefStatusErrorsAndRun(t *testing.T) {
	h, _ := attackRefHandler(t)
	if rec := arGet(h, "POST", "/api/v1/security/attack-ref/entries/status", `{"kind":"path","value":"/nope","status":"rejected"}`); rec.Code != http.StatusNotFound {
		t.Errorf("entrée inconnue : %d", rec.Code)
	}
	if rec := arGet(h, "POST", "/api/v1/security/attack-ref/entries/status", `{"kind":"path","value":"/x","status":"enforce"}`); rec.Code != http.StatusBadRequest {
		t.Errorf("état non posable à l'étape 1 : %d", rec.Code)
	}
	if rec := arGet(h, "POST", "/api/v1/security/attack-ref/entries/status", `pas du json`); rec.Code != http.StatusBadRequest {
		t.Errorf("JSON invalide : %d", rec.Code)
	}
	if rec := arGet(h, "POST", "/api/v1/security/attack-ref/run", ""); rec.Code != http.StatusAccepted {
		t.Errorf("lancement : %d", rec.Code)
	}
	if rec := arGet(h, "DELETE", "/api/v1/security/attack-ref/entries", ""); rec.Code != http.StatusNotFound {
		t.Errorf("méthode inconnue : %d", rec.Code)
	}
}
