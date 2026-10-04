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

func TestTraceScopeFollowsRangeAndASN(t *testing.T) {
	h, db, _, _ := asnHandler(t)
	now := time.Now().UTC().Format(time.RFC3339Nano)
	for _, ip := range []string{"5.0.0.9", "5.0.1.200", "5.0.8.50", "8.8.8.8"} {
		if _, err := db.Exec(`INSERT INTO logs (ts, ip, domain, method, path, status) VALUES (?, ?, 'a.test', 'GET', '/', 200)`, now, ip); err != nil {
			t.Fatal(err)
		}
	}
	// Un ban dans la plage annoncée (5.0.0.0/24) et un autre ailleurs chez le même opérateur (5.0.8.0/25).
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
	rg, _ := ctx["range"].(map[string]any)
	if info["asn"] != float64(64500) || rg["start"] != "5.0.0.0" || rg["end"] != "5.0.1.255" {
		t.Fatalf("contexte ASN : %v", ctx)
	}
	if cidrs, _ := rg["cidrs"].([]any); len(cidrs) != 1 || cidrs[0] != "5.0.0.0/23" {
		t.Errorf("CIDR de la plage : %v", rg["cidrs"])
	}

	// Étendue range : toute la plage annoncée (5.0.0.0 – 5.0.1.255), pas le reste de l'opérateur.
	code, res = traceGet(t, h, "target=5.0.0.9&scope=range")
	if code != http.StatusOK || summaryNum(res, "requests") != 2 || summaryNum(res, "ip_count") != 2 || res["scope_label"] == "" {
		t.Fatalf("range : %d %v", code, res)
	}
	if n := activeBans(res); n != 1 {
		t.Errorf("range : %d ban(s) en cours, 1 attendu (celui de la plage)", n)
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
	// Adresse absente du jeu de données : le traçage simple marche, sans contexte ; range et asn échouent.
	code, res := traceGet(t, h, "target=8.8.8.8")
	if code != http.StatusOK || res["asn_context"] != nil {
		t.Errorf("ip hors jeu de données : %d %v", code, res["asn_context"])
	}
	for _, scope := range []string{"range", "asn"} {
		if code, _ := traceGet(t, h, "target=8.8.8.8&scope="+scope); code != http.StatusNotFound {
			t.Errorf("scope %s sur une adresse inconnue : %d", scope, code)
		}
	}
	if code, _ := traceGet(t, h, "target=5.0.0.9&scope=nimporte"); code != http.StatusBadRequest {
		t.Errorf("scope inconnu : %d", code)
	}

	// Sans base ASN configurée : traçage simple intact, range et asn indisponibles (503).
	none := &api.SecurityHandler{DB: openBansDB(t)}
	if code, res := traceGet(t, none, "target=5.0.0.9"); code != http.StatusOK || res["asn_context"] != nil {
		t.Errorf("sans base : %d", code)
	}
	if code, _ := traceGet(t, none, "target=5.0.0.9&scope=range"); code != http.StatusServiceUnavailable {
		t.Errorf("sans base, range : %d", code)
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
