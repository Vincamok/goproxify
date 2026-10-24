// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/asn"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func traceGet(t *testing.T, h http.Handler, query string) (int, map[string]any) {
	t.Helper()
	rec := banRequest(h, http.MethodGet, "/api/v1/security/ip-trace?"+query, "", "198.51.100.9:1")
	var res map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	return rec.Code, res
}

func summaryNum(res map[string]any, key string) float64 {
	s, _ := res["summary"].(map[string]any)
	v, _ := s[key].(float64)
	return v
}

func TestTraceScopeFollowsASN(t *testing.T) {
	h, db, _, _ := asnHandler(t)
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	h.Edge = &prismedge.Source{DB: db}
	now := time.Now().UTC()
	for _, ip := range []string{"5.0.0.9", "5.0.1.200", "5.0.8.50", "8.8.8.8"} {
		gw.Add(logstore.Entry{Ts: now, IP: ip, Domain: "a.test", Method: "GET", Path: "/", Status: 200})
	}
	// Deux bans chez le même opérateur : l'un dans la plage de l'adresse (5.0.0.0/24), l'autre ailleurs (5.0.8.0/25).
	for id, ip := range map[string]string{"dans": "5.0.0.0/24", "ailleurs": "5.0.8.0/25"} {
		if _, err := db.Exec(`INSERT INTO security_bans (id, ip, source) VALUES (?, ?, 'native')`, id, ip); err != nil {
			t.Fatal(err)
		}
	}
	activeBans := func(res map[string]any) int {
		s, _ := res["summary"].(map[string]any)
		l, _ := s["active_bans"].([]any)
		return len(l)
	}

	// Étendue ip : l'adresse seule, avec son contexte ASN.
	code, res := traceGet(t, h, "target=5.0.0.9")
	if code != http.StatusOK || summaryNum(res, "requests") != 1 || res["scope"] != "ip" {
		t.Fatalf("ip : %d %v", code, res)
	}
	ctx, _ := res["asn_context"].(map[string]any)
	info, _ := ctx["asn"].(map[string]any)
	if info["asn"] != float64(64500) || ctx["range"] != nil {
		t.Fatalf("contexte ASN : %v", ctx)
	}

	// Une étendue range n'existe plus : seuls ip et asn sont acceptés.
	if code, _ := traceGet(t, h, "target=5.0.0.9&scope=range"); code != http.StatusBadRequest {
		t.Errorf("scope range : %d", code)
	}

	// Étendue asn : toutes les plages de l'opérateur.
	code, res = traceGet(t, h, "target=5.0.0.9&scope=asn")
	if code != http.StatusOK || summaryNum(res, "requests") != 3 || summaryNum(res, "ip_count") != 3 {
		t.Fatalf("asn : %d %v", code, res)
	}
	if n := activeBans(res); n != 2 {
		t.Errorf("asn : %d ban(s) en cours, 2 attendus", n)
	}

	// ASN désigné par son numéro, sans adresse.
	code, res = traceGet(t, h, "asn=AS64500&scope=asn")
	if code != http.StatusOK || summaryNum(res, "requests") != 3 || res["kind"] != "asn" {
		t.Fatalf("asn sans cible : %d %v", code, res)
	}
	if code, _ := traceGet(t, h, "asn=AS64500"); code != http.StatusBadRequest {
		t.Errorf("asn sans scope=asn : %d", code)
	}
	if code, _ := traceGet(t, h, "asn=AS64999&scope=asn"); code != http.StatusNotFound {
		t.Errorf("ASN inconnu : %d", code)
	}
}

func TestTraceScopeUnknownAddressAndMissingDatabase(t *testing.T) {
	h, _, _, _ := asnHandler(t)
	// Adresse absente du jeu de données : le traçage simple marche, sans contexte ; asn échoue.
	code, res := traceGet(t, h, "target=8.8.8.8")
	if code != http.StatusOK || res["asn_context"] != nil {
		t.Errorf("ip hors jeu de données : %d %v", code, res["asn_context"])
	}
	if code, _ := traceGet(t, h, "target=8.8.8.8&scope=asn"); code != http.StatusNotFound {
		t.Errorf("scope asn sur une adresse inconnue : %d", code)
	}
	if code, _ := traceGet(t, h, "target=5.0.0.9&scope=nimporte"); code != http.StatusBadRequest {
		t.Errorf("scope inconnu : %d", code)
	}

	// Sans base ASN configurée : traçage simple intact, asn indisponible (503).
	none := &api.SecurityHandler{DB: openBansDB(t)}
	if code, res := traceGet(t, none, "target=5.0.0.9"); code != http.StatusOK || res["asn_context"] != nil {
		t.Errorf("sans base : %d", code)
	}
	if code, _ := traceGet(t, none, "target=5.0.0.9&scope=asn"); code != http.StatusServiceUnavailable {
		t.Errorf("sans base, asn : %d", code)
	}

	// Base non installée : un traçage simple ne déclenche aucun téléchargement.
	hits := 0
	srvStore := asn.NewStore(filepath.Join(t.TempDir(), "absent.tsv.gz"), "http://127.0.0.1:1/jamais", nil)
	notInstalled := &api.SecurityHandler{DB: openBansDB(t), ASN: srvStore}
	start := time.Now()
	if code, res := traceGet(t, notInstalled, "target=5.0.0.9"); code != http.StatusOK || res["asn_context"] != nil || time.Since(start) > 2*time.Second {
		t.Errorf("base non installée : %d, %v", code, time.Since(start))
	}
	if srvStore.Info().Installed || hits != 0 {
		t.Error("le traçage simple a installé la base")
	}
}
