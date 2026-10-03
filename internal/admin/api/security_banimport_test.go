// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
)

func doImport(t *testing.T, h http.Handler, req api.ImportRequest, remote string) (api.ImportResult, int, string) {
	t.Helper()
	body, _ := json.Marshal(req)
	rec := banRequest(h, http.MethodPost, "/api/v1/security/bans/import", string(body), remote)
	var res api.ImportResult
	if rec.Code == http.StatusOK {
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatalf("%v : %s", err, rec.Body)
		}
	}
	return res, rec.Code, rec.Body.String()
}

func banValues(t *testing.T, db *sql.DB) map[string]bool {
	t.Helper()
	rows, err := db.Query(`SELECT ip FROM security_bans`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]bool{}
	for rows.Next() {
		var ip string
		_ = rows.Scan(&ip)
		out[ip] = true
	}
	return out
}

func issueReason(list []api.ImportIssue, value string) string {
	for _, i := range list {
		if i.Value == value {
			return i.Reason
		}
	}
	return ""
}

const importList = `# liste de test
203.0.113.5 ; scanner SSH
198.51.100.0/24
pas-une-ip
10.0.0.0/8
203.0.113.5
192.168.1.0/24
192.0.2.0/24
192.0.2.77
100.64.5.0/24
2001:DB8::/48
`

func TestImportCreatesBansAndReportsEveryLine(t *testing.T) {
	db := openBansDB(t)
	var pushes atomic.Int32
	h := &api.SecurityHandler{DB: db, OnBansChange: func() { pushes.Add(1) }}
	// Contexte : un ban actif qui couvre 100.64.0.0/16, une plage en liste blanche, un appelant dans 198.51.100.0/24.
	for _, q := range []string{
		`INSERT INTO security_bans (id, ip, source) VALUES ('wide', '100.64.0.0/16', 'native')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	wlAdd(h, `{"ip":"192.0.2.0/24"}`)

	res, code, body := doImport(t, h, api.ImportRequest{Content: importList, Reason: "liste test"}, "198.51.100.9:1")
	if code != http.StatusOK {
		t.Fatalf("status %d %s", code, body)
	}
	if res.Format != "text" || res.Target != "bans" || res.Total != 10 {
		t.Fatalf("en-tête : %+v", res)
	}
	// Créés : 203.0.113.5 et 2001:db8::/48.
	if res.Created != 2 {
		t.Fatalf("créés : %d (%v)", res.Created, res.Sample)
	}
	got := banValues(t, db)
	if !got["203.0.113.5"] || !got["2001:db8::/48"] || len(got) != 3 { // + le ban 'wide' préexistant
		t.Fatalf("bans en base : %v", got)
	}
	wantRejected := map[string]string{
		"pas-une-ip":      "invalide",
		"10.0.0.0/8":      "trop large",
		"198.51.100.0/24": "votre propre adresse",
	}
	for v, why := range wantRejected {
		if r := issueReason(res.Rejected, v); !strings.Contains(r, why) {
			t.Errorf("rejet de %q : %q, attendu %q", v, r, why)
		}
	}
	wantSkipped := map[string]string{
		"192.168.1.0/24": "privée",
		"192.0.2.0/24":   "liste blanche",
		"192.0.2.77":     "liste blanche",
		"100.64.5.0/24":  "déjà couvert par le ban 100.64.0.0/16",
	}
	for v, why := range wantSkipped {
		if r := issueReason(res.Skipped, v); !strings.Contains(r, why) {
			t.Errorf("entrée ignorée %q : %q, attendu %q", v, r, why)
		}
	}
	if issueReason(res.Skipped, "203.0.113.5") != "doublon dans la liste" {
		t.Errorf("doublon : %+v", res.Skipped)
	}
	if res.RejectedCount != 3 || res.SkippedCount != 5 {
		t.Errorf("compteurs : rejetés=%d ignorés=%d", res.RejectedCount, res.SkippedCount)
	}
	// Motif repris du commentaire de la ligne, sinon du motif par défaut ; historique alimenté.
	var reason string
	_ = db.QueryRow(`SELECT reason FROM security_bans WHERE ip='203.0.113.5'`).Scan(&reason)
	var other string
	_ = db.QueryRow(`SELECT reason FROM security_bans WHERE ip='2001:db8::/48'`).Scan(&other)
	if reason != "scanner SSH" || other != "liste test" {
		t.Errorf("motifs : %q %q", reason, other)
	}
	var hist int
	_ = db.QueryRow(`SELECT COUNT(*) FROM security_ban_history WHERE action='banned'`).Scan(&hist)
	if hist != 2 {
		t.Errorf("historique : %d", hist)
	}
	if pushes.Load() != 1 {
		t.Errorf("poussées vers les passerelles : %d, attendu 1 pour tout le lot", pushes.Load())
	}
	if res.Addresses < 1 {
		t.Errorf("adresses : %v", res.Addresses)
	}
}

func TestImportDryRunWritesNothing(t *testing.T) {
	db := openBansDB(t)
	var pushes atomic.Int32
	h := &api.SecurityHandler{DB: db, OnBansChange: func() { pushes.Add(1) }}
	res, code, _ := doImport(t, h, api.ImportRequest{Content: "203.0.113.5\n203.0.113.0/24\n198.51.100.1\n", DryRun: true}, "192.0.2.1:1")
	if code != http.StatusOK || !res.DryRun {
		t.Fatalf("%d %+v", code, res)
	}
	// 203.0.113.5 est couvert par la plage de la même liste.
	if res.Created != 2 || issueReason(res.Skipped, "203.0.113.5") != "couvert par 203.0.113.0/24 dans la même liste" {
		t.Fatalf("analyse : créés=%d ignorés=%+v", res.Created, res.Skipped)
	}
	if len(banValues(t, db)) != 0 || pushes.Load() != 0 {
		t.Fatalf("dry_run a écrit : %v, poussées %d", banValues(t, db), pushes.Load())
	}
	var audits int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='import_bans'`).Scan(&audits)
	if audits != 0 {
		t.Fatal("une analyse ne s'audite pas")
	}
	// Le même contenu, importé pour de bon, donne le même résultat et s'audite.
	real, _, _ := doImport(t, h, api.ImportRequest{Content: "203.0.113.5\n203.0.113.0/24\n198.51.100.1\n"}, "192.0.2.1:1")
	if real.Created != 2 || len(banValues(t, db)) != 2 {
		t.Fatalf("import réel : %+v %v", real, banValues(t, db))
	}
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='import_bans'`).Scan(&audits)
	if audits != 1 {
		t.Fatalf("audit : %d", audits)
	}
}

func TestImportExpirations(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}
	csv := "ip,reason,expires_at\n203.0.113.5,a,2027-01-01T00:00:00+01:00\n203.0.113.6,b,\n203.0.113.7,c,demain\n"
	res, code, _ := doImport(t, h, api.ImportRequest{Content: csv, ExpiresAt: "2026-12-31T23:59:59.000Z"}, "192.0.2.1:1")
	if code != http.StatusOK || res.Format != "csv" || res.Created != 2 || res.RejectedCount != 1 {
		t.Fatalf("%d %+v", code, res)
	}
	exp := func(ip string) string {
		var e sql.NullString
		_ = db.QueryRow(`SELECT expires_at FROM security_bans WHERE ip=?`, ip).Scan(&e)
		return e.String
	}
	if exp("203.0.113.5") != "2026-12-31T23:00:00Z" { // propre à la ligne, ramené en UTC
		t.Errorf("expiration de la ligne : %q", exp("203.0.113.5"))
	}
	if exp("203.0.113.6") != "2026-12-31T23:59:59Z" { // défaut de la requête
		t.Errorf("expiration par défaut : %q", exp("203.0.113.6"))
	}
	if !strings.Contains(issueReason(res.Rejected, "203.0.113.7"), "expires_at invalide") {
		t.Errorf("expiration illisible : %+v", res.Rejected)
	}
	if _, code, _ := doImport(t, h, api.ImportRequest{Content: "203.0.113.9", ExpiresAt: "demain"}, "192.0.2.1:1"); code != http.StatusBadRequest {
		t.Errorf("expiration par défaut illisible : %d", code)
	}
}

func TestImportToWhitelist(t *testing.T) {
	db := openBansDB(t)
	var wlPush, banPush atomic.Int32
	h := &api.SecurityHandler{DB: db, OnWhitelistChange: func() { wlPush.Add(1) }, OnBansChange: func() { banPush.Add(1) }}
	wlAdd(h, `{"ip":"203.0.113.0/24"}`)
	wlPush.Store(0)

	list := "203.0.113.50 ; déjà couvert\n198.51.100.0/24 ; bureau\n198.51.100.9\n192.0.2.4\n10.0.0.0/8\n"
	res, code, body := doImport(t, h, api.ImportRequest{Content: list, Target: "whitelist", Reason: "partenaires"}, "198.51.100.9:1")
	if code != http.StatusOK {
		t.Fatalf("%d %s", code, body)
	}
	// Créés : 198.51.100.0/24 (le /32 est couvert par lui) et 192.0.2.4 ; l'appelant peut s'exempter lui-même.
	if res.Created != 2 || res.RejectedCount != 1 {
		t.Fatalf("liste blanche : créés=%d rejetés=%+v ignorés=%+v", res.Created, res.Rejected, res.Skipped)
	}
	got := map[string]string{}
	for _, e := range wlList(t, h) {
		got[e.Value] = e.Comment
	}
	if got["198.51.100.0/24"] != "bureau" || got["192.0.2.4"] != "partenaires" || len(got) != 3 {
		t.Fatalf("entrées : %v", got)
	}
	if wlPush.Load() != 1 || banPush.Load() != 0 {
		t.Fatalf("poussées : liste blanche=%d bans=%d", wlPush.Load(), banPush.Load())
	}
	if len(banValues(t, db)) != 0 {
		t.Fatal("aucun ban ne doit être créé en visant la liste blanche")
	}
}

// Le CSV de l'export se réimporte tel quel, et un second import est sans effet.
func TestImportRoundTripOfExport(t *testing.T) {
	src := openBansDB(t)
	hs := &api.SecurityHandler{DB: src}
	for _, ip := range []string{"203.0.113.5", "198.51.0.0/16", "2001:db8:1::/48"} {
		if rec := banRequest(hs, http.MethodPost, "/api/v1/security/bans", `{"ip":"`+ip+`","reason":"abus"}`, "192.0.2.1:1"); rec.Code != http.StatusCreated {
			t.Fatalf("%s : %d", ip, rec.Code)
		}
	}
	exp := banRequest(hs, http.MethodGet, "/api/v1/security/bans/export?format=csv", "", "192.0.2.1:1")
	if exp.Code != http.StatusOK {
		t.Fatalf("export : %d", exp.Code)
	}

	dst := openBansDB(t)
	hd := &api.SecurityHandler{DB: dst}
	res, code, body := doImport(t, hd, api.ImportRequest{Content: exp.Body.String()}, "192.0.2.1:1")
	if code != http.StatusOK || res.Format != "csv" || res.Created != 3 || res.RejectedCount != 0 {
		t.Fatalf("réimport : %d %+v %s", code, res, body)
	}
	if got := banValues(t, dst); len(got) != 3 || !got["198.51.0.0/16"] {
		t.Fatalf("bans réimportés : %v", got)
	}
	again, _, _ := doImport(t, hd, api.ImportRequest{Content: exp.Body.String()}, "192.0.2.1:1")
	if again.Created != 0 || again.SkippedCount != 3 {
		t.Fatalf("second import : créés=%d ignorés=%d, attendu 0 et 3", again.Created, again.SkippedCount)
	}
}

func TestImportRejectsBadRequests(t *testing.T) {
	h := &api.SecurityHandler{DB: openBansDB(t)}
	for name, req := range map[string]api.ImportRequest{
		"vide":            {Content: ""},
		"que des notes":   {Content: "# rien\n"},
		"target inconnue": {Content: "203.0.113.5", Target: "autre"},
		"format inconnu":  {Content: "203.0.113.5", Format: "xml"},
		"json invalide":   {Content: "[{", Format: "json"},
	} {
		if _, code, _ := doImport(t, h, req, "192.0.2.1:1"); code != http.StatusBadRequest {
			t.Errorf("%s : %d, attendu 400", name, code)
		}
	}
	rec := banRequest(h, http.MethodPost, "/api/v1/security/bans/import", "pas du json", "192.0.2.1:1")
	if rec.Code != http.StatusBadRequest {
		t.Errorf("corps illisible : %d", rec.Code)
	}
}
