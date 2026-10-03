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

	"github.com/vincamok/goproxify/internal/admin/api"
)

func banRequest(h http.Handler, method, path, body, remote string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = remote
	h.ServeHTTP(rec, req)
	return rec
}

func storedBanIP(t *testing.T, db *sql.DB, id string) string {
	t.Helper()
	var ip string
	if err := db.QueryRow(`SELECT ip FROM security_bans WHERE id=?`, id).Scan(&ip); err != nil {
		t.Fatal(err)
	}
	return ip
}

// Une plage est enregistrée sous sa forme normalisée : deux saisies de la même plage ne divergent pas.
func TestCreateBanAcceptsAndNormalizesCIDR(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	for body, want := range map[string]string{
		`{"ip":"203.0.113.7/24"}`:        "203.0.113.0/24",
		`{"ip":" 198.51.100.0/24 "}`:     "198.51.100.0/24",
		`{"ip":"2001:DB8:1:1::5/64"}`:    "2001:db8:1:1::/64",
		`{"ip":"192.0.2.9/32"}`:          "192.0.2.9",
		`{"ip":"2001:DB8::1"}`:           "2001:db8::1",
		`{"ip":"198.18.0.0/16"}`:         "198.18.0.0/16",
	} {
		rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", body, "198.51.99.1:5000")
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s : status %d %s", body, rec.Code, rec.Body)
		}
		var res struct{ ID string }
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if got := storedBanIP(t, db, res.ID); got != want {
			t.Errorf("%s : enregistré %q, attendu %q", body, got, want)
		}
	}
}

// Une valeur illisible n'est plus enregistrée : la passerelle l'aurait ignorée sans rien dire.
func TestCreateBanRejectsInvalidAndTooBroad(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	for _, ip := range []string{"pas-une-ip", "203.0.113.256", "203.0.113.0/33", "10.0.0.0/8", "0.0.0.0/0", "::/0", "198.51.0.0/15", "2001:db8::/31", "203.0.113.1-9"} {
		rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"`+ip+`"}`, "198.51.99.1:5000")
		if rec.Code != http.StatusBadRequest {
			t.Errorf("%q : status %d, attendu 400 (%s)", ip, rec.Code, rec.Body)
		}
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM security_bans`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Fatalf("%d ban(s) enregistré(s) malgré le refus", n)
	}
	if rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{}`, "198.51.99.1:5000"); rec.Code != http.StatusBadRequest || !strings.Contains(rec.Body.String(), "ip requis") {
		t.Errorf("ip absente : %d %q", rec.Code, rec.Body)
	}
}

// Une plage qui contient l'adresse de l'appelant est refusée (409), une adresse seule reste permise.
func TestCreateBanRefusesRangeContainingCaller(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.113.0/24"}`, "203.0.113.77:41000")
	if rec.Code != http.StatusConflict || !strings.Contains(rec.Body.String(), "203.0.113.77") {
		t.Fatalf("plage contenant l'appelant : %d %q", rec.Code, rec.Body)
	}
	// Derrière un proxy de confiance, c'est l'adresse transmise qui compte.
	req := httptest.NewRequest(http.MethodPost, "/api/v1/security/bans", strings.NewReader(`{"ip":"203.0.113.0/24"}`))
	req.RemoteAddr = "10.0.0.5:1234"
	req.Header.Set("X-Forwarded-For", "203.0.113.77")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusConflict {
		t.Fatalf("X-Forwarded-For : %d %q", rec.Code, rec.Body)
	}
	if rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.113.0/24"}`, "198.51.100.9:1"); rec.Code != http.StatusCreated {
		t.Fatalf("appelant hors plage : %d %q", rec.Code, rec.Body)
	}
	if rec := banRequest(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.113.77"}`, "203.0.113.77:1"); rec.Code != http.StatusCreated {
		t.Fatalf("adresse seule : %d %q", rec.Code, rec.Body)
	}
}

type previewRes struct {
	Target      string `json:"target"`
	Kind        string `json:"kind"`
	Addresses   float64
	Requests    int `json:"requests"`
	Blocked     int `json:"blocked"`
	OKRequests  int `json:"ok_requests"`
	IPs         int `json:"ips"`
	OKIPs       int `json:"ok_ips"`
	Private     bool
	RequesterIn bool `json:"requester_in"`
	TopIPs      []struct {
		Value string
		Count int
	} `json:"top_ips"`
	ExistingBans []struct {
		IP       string `json:"ip"`
		Relation string `json:"relation"`
	} `json:"existing_bans"`
	Profiles []struct {
		Name string `json:"name"`
		Mode string `json:"mode"`
	} `json:"profiles"`
	Warnings []string `json:"warnings"`
}

func getPreview(t *testing.T, h http.Handler, query, remote string) (previewRes, int) {
	t.Helper()
	rec := banRequest(h, http.MethodGet, "/api/v1/security/bans/preview?"+query, "", remote)
	var res previewRes
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("%v : %s", err, rec.Body)
		}
	}
	return res, rec.Code
}

func hasWarning(res previewRes, sub string) bool {
	for _, w := range res.Warnings {
		if strings.Contains(w, sub) {
			return true
		}
	}
	return false
}

func TestBanPreviewMeasuresImpact(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	at := time.Now().UTC().Add(-time.Hour).Format(time.RFC3339)
	log := func(ip string, status int, waf string) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO logs (ts, ip, domain, method, path, status, waf_matches) VALUES (?, ?, 'a.test', 'GET', '/x', ?, ?)`, at, ip, status, waf); err != nil {
			t.Fatal(err)
		}
	}
	// Dans 203.0.113.0/24 : un scanner (bloqué) et un visiteur légitime (200). Hors plage : ignoré.
	for i := 0; i < 5; i++ {
		log("203.0.113.5", 403, "")
	}
	log("203.0.113.5", 404, `["sqli"]`)
	log("203.0.113.9", 200, "")
	log("203.0.113.9", 200, "")
	log("198.51.100.1", 200, "")
	// Plus ancien que la fenêtre : ignoré.
	old := time.Now().UTC().Add(-72 * time.Hour).Format(time.RFC3339)
	if _, err := db.Exec(`INSERT INTO logs (ts, ip, domain, method, path, status) VALUES (?, '203.0.113.200', 'a.test', 'GET', '/', 200)`, old); err != nil {
		t.Fatal(err)
	}

	res, code := getPreview(t, h, "ip=203.0.113.7/24&hours=24", "198.51.100.9:1")
	if code != http.StatusOK {
		t.Fatalf("status %d", code)
	}
	if res.Target != "203.0.113.0/24" || res.Kind != "cidr" || res.Addresses != 256 {
		t.Errorf("cible : %+v", res)
	}
	if res.Requests != 8 || res.Blocked != 6 || res.OKRequests != 2 || res.IPs != 2 || res.OKIPs != 1 {
		t.Errorf("trafic : requests=%d blocked=%d ok=%d ips=%d ok_ips=%d, attendu 8/6/2/2/1", res.Requests, res.Blocked, res.OKRequests, res.IPs, res.OKIPs)
	}
	if len(res.TopIPs) == 0 || res.TopIPs[0].Value != "203.0.113.5" {
		t.Errorf("top IP : %+v", res.TopIPs)
	}
	if !hasWarning(res, "2 requête(s) réussie(s) de 1 adresse(s) seraient coupées") {
		t.Errorf("avertissement sur le trafic légitime : %v", res.Warnings)
	}
	// Sans aucune création.
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM security_bans`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Fatalf("l'aperçu a créé %d ban(s)", n)
	}
}

func TestBanPreviewFlagsRisks(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO security_bans (id, ip, source) VALUES ('wide', '203.0.0.0/16', 'native')`)
	exec(`INSERT INTO security_bans (id, ip, source) VALUES ('narrow', '203.0.113.64/26', 'native')`)
	exec(`INSERT INTO security_bans (id, ip, source) VALUES ('elsewhere', '198.51.100.0/24', 'native')`)
	exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES ('expired', '203.0.113.0/24', 'native', '2000-01-01T00:00:00Z')`)
	exec(`INSERT INTO ip_profiles (id, name, profile_type, mode, cidrs, enabled) VALUES ('vip', 'Partenaires', 'custom', 'allow', '["203.0.113.128/25"]', 1)`)
	exec(`INSERT INTO ip_profiles (id, name, profile_type, mode, cidrs, enabled) VALUES ('off', 'Désactivé', 'custom', 'allow', '["203.0.113.0/24"]', 0)`)

	res, _ := getPreview(t, h, "ip=203.0.113.0/24", "203.0.113.77:1")
	rel := map[string]string{}
	for _, b := range res.ExistingBans {
		rel[b.IP] = b.Relation
	}
	if rel["203.0.0.0/16"] != "covers" || rel["203.0.113.64/26"] != "inside" || len(rel) != 2 {
		t.Errorf("bans qui recoupent (expiré et étranger exclus) : %v", rel)
	}
	if len(res.Profiles) != 1 || res.Profiles[0].Name != "Partenaires" {
		t.Errorf("profils actifs qui recoupent : %+v", res.Profiles)
	}
	for _, sub := range []string{"votre adresse (203.0.113.77)", "déjà couvert par le ban 203.0.0.0/16", "englobe 1 ban(s)", "profil IP en mode allow", "aucun trafic"} {
		if !hasWarning(res, sub) {
			t.Errorf("avertissement %q absent : %v", sub, res.Warnings)
		}
	}
	if !res.RequesterIn {
		t.Error("requester_in doit signaler l'auto-verrouillage")
	}

	priv, _ := getPreview(t, h, "ip=192.168.1.0/24", "198.51.100.9:1")
	if !priv.Private || !hasWarning(priv, "plage privée") {
		t.Errorf("plage privée : %+v", priv)
	}
	same, _ := getPreview(t, h, "ip=198.51.100.0/24", "198.51.100.9:1")
	if !hasWarning(same, "déjà banni") {
		t.Errorf("même plage : %v", same.Warnings)
	}
}

func TestBanPreviewRejectsInvalidTarget(t *testing.T) {
	h := &api.SecurityHandler{DB: openBansDB(t)}
	for _, q := range []string{"", "ip=nope", "ip=10.0.0.0/8", "ip=0.0.0.0/0"} {
		if _, code := getPreview(t, h, q, "198.51.100.9:1"); code != http.StatusBadRequest {
			t.Errorf("%q : status %d, attendu 400", q, code)
		}
	}
}
