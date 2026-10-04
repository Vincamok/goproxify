// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"bytes"
	"compress/gzip"
	"database/sql"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/asn"
)

const asnSample = "5.0.0.0\t5.0.1.255\t64500\tFR\tEXEMPLE-HEBERGEUR\n" +
	"5.0.8.0\t5.0.8.127\t64500\tFR\tEXEMPLE-HEBERGEUR\n" +
	"2a00:1450::\t2a00:1450:ffff:ffff:ffff:ffff:ffff:ffff\t64500\tFR\tEXEMPLE-HEBERGEUR\n" +
	"9.0.0.0\t9.1.255.255\t64501\tDE\tGRAND-OPERATEUR\n" +
	"11.0.0.0\t11.0.0.255\t64502\tUS\tPETIT-RESEAU\n"

// asnStore installe un jeu de données de test sur disque : aucun téléchargement.
func asnStore(t *testing.T) *asn.Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "ip2asn.tsv.gz")
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(asnSample))
	_ = zw.Close()
	if err := os.WriteFile(path, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return asn.NewStore(path, "http://127.0.0.1:1/inaccessible", nil)
}

func asnHandler(t *testing.T) (*api.SecurityHandler, *sql.DB, *atomic.Int32, *[]string) {
	t.Helper()
	db := openBansDB(t)
	var pushes atomic.Int32
	var lifted []string
	h := &api.SecurityHandler{
		DB: db, ASN: asnStore(t),
		OnBansChange: func() { pushes.Add(1) },
		OnUnbanMany:  func(ips []string) { lifted = append(lifted, ips...) },
	}
	return h, db, &pushes, &lifted
}

func asnCall(h http.Handler, method, path, body, remote string) (int, map[string]any, []map[string]any) {
	rec := banRequest(h, method, path, body, remote)
	var obj map[string]any
	var list []map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &obj)
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	return rec.Code, obj, list
}

func TestASNLookup(t *testing.T) {
	h, _, _, _ := asnHandler(t)
	for q, want := range map[string]float64{"AS64500": 64500, "64501": 64501, "5.0.1.9": 64500, "2a00:1450::1": 64500, "grand": 64501} {
		code, _, list := asnCall(h, http.MethodGet, "/api/v1/security/asn?q="+q, "", "198.51.100.9:1")
		if code != http.StatusOK || len(list) != 1 || list[0]["asn"] != want {
			t.Errorf("%q : %d %v", q, code, list)
		}
	}
	code, _, list := asnCall(h, http.MethodGet, "/api/v1/security/asn?q=8.8.8.8", "", "198.51.100.9:1")
	if code != http.StatusOK || len(list) != 0 {
		t.Errorf("IP sans ASN : %d %v", code, list)
	}
	if code, _, _ := asnCall(h, http.MethodGet, "/api/v1/security/asn?q=", "", "198.51.100.9:1"); code != http.StatusBadRequest {
		t.Errorf("q vide : %d", code)
	}
	l := &api.SecurityHandler{DB: openBansDB(t)}
	if code, _, _ := asnCall(l, http.MethodGet, "/api/v1/security/asn?q=1", "", "198.51.100.9:1"); code != http.StatusServiceUnavailable {
		t.Errorf("sans base ASN : %d", code)
	}
}

func TestBanASNCreatesOneBanPerPrefixAndIsIdempotent(t *testing.T) {
	h, db, pushes, _ := asnHandler(t)
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name) VALUES ('t1', 's', 'edge', 'paris')`); err != nil {
		t.Fatal(err)
	}

	// Simulation : rien n'est écrit.
	code, res, _ := asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"AS64500","dry_run":true}`, "198.51.100.9:1")
	if code != http.StatusOK || res["created"] != float64(3) || res["dry_run"] != true || res["name"] != "EXEMPLE-HEBERGEUR" {
		t.Fatalf("simulation : %d %v", code, res)
	}
	if n := len(banValues(t, db)); n != 0 || pushes.Load() != 0 {
		t.Fatalf("la simulation a écrit %d ban(s), %d envoi(s)", n, pushes.Load())
	}

	// Ban réel : 5.0.0.0/23, 5.0.8.0/25, 2a00:1450::/32 = 3 plages annoncées, 3 CIDR (le /23 reste entier).
	code, res, _ = asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64500","scope":"paris","expires_at":"2099-01-01T00:00:00Z"}`, "198.51.100.9:1")
	if code != http.StatusOK {
		t.Fatalf("ban : %d %v", code, res)
	}
	if res["created"] != float64(3) || res["announced_ranges"] != float64(3) || res["prefixes"] != float64(3) {
		t.Fatalf("rapport : %v", res)
	}
	got := banValues(t, db)
	for _, want := range []string{"5.0.0.0/23", "5.0.8.0/25", "2a00:1450::/32"} {
		if !got[want] {
			t.Errorf("%s absent : %v", want, got)
		}
	}
	var scope, reason string
	var asnNum int
	if err := db.QueryRow(`SELECT target_scope, reason, asn FROM security_bans WHERE ip='5.0.8.0/25'`).Scan(&scope, &reason, &asnNum); err != nil {
		t.Fatal(err)
	}
	if scope != "paris" || asnNum != 64500 || !strings.Contains(reason, "AS64500") || !strings.Contains(reason, "EXEMPLE-HEBERGEUR") {
		t.Errorf("ban : scope %q, asn %d, motif %q", scope, asnNum, reason)
	}
	if pushes.Load() != 1 {
		t.Errorf("%d envoi(s) aux passerelles, un seul attendu pour tout le lot", pushes.Load())
	}

	// Relancer : plus rien à créer, pas de doublon.
	code, res, _ = asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64500"}`, "198.51.100.9:1")
	if code != http.StatusOK || res["created"] != float64(0) || res["skipped_count"] != float64(3) || len(banValues(t, db)) != 3 {
		t.Errorf("second ban : %d %v", code, res)
	}

	// La liste des bans expose l'ASN.
	rec := banRequest(h, http.MethodGet, "/api/v1/security/bans", "", "198.51.100.9:1")
	if strings.Count(rec.Body.String(), `"asn":64500`) != 3 {
		t.Errorf("liste : %s", rec.Body)
	}
}

func TestBanASNSplitsWidePrefixesAndKeepsWhitelist(t *testing.T) {
	h, db, _, _ := asnHandler(t)
	wlAdd(h, `{"ip":"9.0.5.0/24"}`)
	// 9.0.0.0–9.1.255.255 = /15 : deux /16 ; le premier contient l'entrée de liste blanche mais ne lui est pas égal.
	_, res, _ := asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"AS64501"}`, "198.51.100.9:1")
	if res["created"] != float64(2) {
		t.Fatalf("%v", res)
	}
	got := banValues(t, db)
	if !got["9.0.0.0/16"] || !got["9.1.0.0/16"] {
		t.Errorf("découpage en /16 : %v", got)
	}
}

func TestBanASNRefusesRequesterRangeUnknownAndInvalid(t *testing.T) {
	h, db, _, _ := asnHandler(t)
	if code, _, _ := asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64500"}`, "5.0.0.77:1234"); code != http.StatusConflict {
		t.Errorf("l'appelant est dans l'ASN : %d", code)
	}
	if n := len(banValues(t, db)); n != 0 {
		t.Errorf("%d ban(s) créé(s) malgré le refus", n)
	}
	if code, _, _ := asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64999"}`, "198.51.100.9:1"); code != http.StatusNotFound {
		t.Errorf("ASN inconnu : %d", code)
	}
	for _, bad := range []string{`{"asn":""}`, `{"asn":"AS0"}`, `{"asn":"abc"}`, `{"asn":"64500","expires_at":"demain"}`, `{"asn":"64500","scope":"nulle-part"}`} {
		if code, _, _ := asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", bad, "198.51.100.9:1"); code != http.StatusBadRequest {
			t.Errorf("%s : %d", bad, code)
		}
	}
	l := &api.SecurityHandler{DB: db}
	if code, _, _ := asnCall(l, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64500"}`, "198.51.100.9:1"); code != http.StatusServiceUnavailable {
		t.Errorf("sans base ASN : %d", code)
	}
}

func TestUnbanASNRemovesOnlyThatASN(t *testing.T) {
	h, db, pushes, lifted := asnHandler(t)
	asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64500"}`, "198.51.100.9:1")
	asnCall(h, http.MethodPost, "/api/v1/security/asn/ban", `{"asn":"64502"}`, "198.51.100.9:1")
	if _, err := db.Exec(`INSERT INTO security_bans (id, ip, source) VALUES ('manuel', '5.0.0.0/24', 'native')`); err != nil {
		t.Fatal(err)
	}
	before := pushes.Load()

	code, res, _ := asnCall(h, http.MethodDelete, "/api/v1/security/asn/ban?asn=AS64500", "", "198.51.100.9:1")
	if code != http.StatusOK || res["removed"] != float64(3) {
		t.Fatalf("déban : %d %v", code, res)
	}
	got := banValues(t, db)
	if len(got) != 2 || !got["11.0.0.0/24"] || !got["5.0.0.0/24"] {
		t.Errorf("bans restants : %v", got)
	}
	if len(*lifted) != 3 || pushes.Load() != before {
		t.Errorf("levée groupée : %v, %d envoi(s) de liste en plus", *lifted, pushes.Load()-before)
	}
	var history int
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_ban_history WHERE action='unbanned'`).Scan(&history)
	if history != 3 {
		t.Errorf("historique : %d", history)
	}
	if code, res, _ := asnCall(h, http.MethodDelete, "/api/v1/security/asn/ban?asn=64500", "", "198.51.100.9:1"); code != http.StatusOK || res["removed"] != float64(0) {
		t.Errorf("second déban : %d %v", code, res)
	}
	if code, _, _ := asnCall(h, http.MethodDelete, "/api/v1/security/asn/ban", "", "198.51.100.9:1"); code != http.StatusBadRequest {
		t.Errorf("asn manquant : %d", code)
	}
}

func TestASNPreviewMeasuresTrafficAndWarns(t *testing.T) {
	h, db, _, _ := asnHandler(t)
	for _, q := range []string{
		`INSERT INTO logs (ts, domain, ip, status, path) VALUES (strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'a.fr', '5.0.0.9', 200, '/')`,
		`INSERT INTO logs (ts, domain, ip, status, path) VALUES (strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'a.fr', '5.0.1.4', 403, '/x')`,
		`INSERT INTO logs (ts, domain, ip, status, path) VALUES (strftime('%Y-%m-%dT%H:%M:%SZ','now'), 'a.fr', '8.8.8.8', 200, '/')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("insertion des logs de test : %v", err)
		}
	}
	code, res, _ := asnCall(h, http.MethodGet, "/api/v1/security/asn/preview?asn=AS64500", "", "198.51.100.9:1")
	if code != http.StatusOK {
		t.Fatalf("%d %v", code, res)
	}
	if res["requests"] != float64(2) || res["blocked"] != float64(1) || res["ok_requests"] != float64(1) || res["ips"] != float64(2) {
		t.Errorf("trafic : %v", res)
	}
	if res["would_create"] != float64(3) || res["requester_in"] != false {
		t.Errorf("simulation : %v", res)
	}
	if w, _ := json.Marshal(res["warnings"]); !strings.Contains(string(w), "réussie") {
		t.Errorf("avertissements : %s", w)
	}

	_, res, _ = asnCall(h, http.MethodGet, "/api/v1/security/asn/preview?asn=64500", "", "5.0.0.1:1")
	if res["requester_in"] != true {
		t.Errorf("l'appelant est dans l'ASN : %v", res)
	}
	if w, _ := json.Marshal(res["warnings"]); !strings.Contains(string(w), "votre adresse") {
		t.Errorf("avertissement d'auto-verrouillage : %s", w)
	}
}

func TestASNInfoWithoutDatabaseFile(t *testing.T) {
	h := &api.SecurityHandler{DB: openBansDB(t), ASN: asn.NewStore(filepath.Join(t.TempDir(), "absent.tsv.gz"), "http://127.0.0.1:1/x", nil)}
	code, res, _ := asnCall(h, http.MethodGet, "/api/v1/security/asn/info", "", "198.51.100.9:1")
	if code != http.StatusOK || res["installed"] != false {
		t.Errorf("info : %d %v", code, res)
	}
	// Téléchargement impossible : erreur lisible (503), pas de panique.
	if code, _, _ := asnCall(h, http.MethodGet, "/api/v1/security/asn?q=64500", "", "198.51.100.9:1"); code != http.StatusServiceUnavailable {
		t.Errorf("base absente et injoignable : %d", code)
	}
}
