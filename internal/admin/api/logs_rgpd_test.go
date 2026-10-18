// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/gdpr"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

type rgpdFixture struct {
	t     *testing.T
	db    *sql.DB
	store *logs.Store
	h     http.Handler
}

func newRGPDFixture(t *testing.T) *rgpdFixture {
	t.Helper()
	db := openSQLDatesDB(t)
	for _, u := range []struct{ id, role string }{{"sa", "superadmin"}, {"a", "admin"}} {
		if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, 'x', ?)`, u.id, u.id+"@t.local", u.role); err != nil {
			t.Fatal(err)
		}
	}
	key, err := gdpr.EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	store := logs.New(db)
	store.SetGDPRKey(key)
	h := adminauth.RequireJWT("secret")(&LogsHandler{Log: slog.Default(), Store: store, DB: db})
	return &rgpdFixture{t: t, db: db, store: store, h: h}
}

func (f *rgpdFixture) do(method, path, user string, body any) *httptest.ResponseRecorder {
	f.t.Helper()
	b, _ := json.Marshal(body)
	tok, err := adminauth.SignJWT(user, "secret", time.Hour)
	if err != nil {
		f.t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, bytes.NewReader(b))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	f.h.ServeHTTP(rec, req)
	return rec
}

func (f *rgpdFixture) auditCount(action string) int {
	var n int
	f.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = ?`, action).Scan(&n) //nolint:errcheck
	return n
}

func TestLogsSettingsRejectsBothIPModes(t *testing.T) {
	f := newRGPDFixture(t)
	steps := []struct {
		body map[string]any
		want int
	}{
		{map[string]any{"ip_anonymize": true, "ip_pseudonymize": true}, http.StatusBadRequest},
		{map[string]any{"ip_pseudonymize": true}, http.StatusNoContent},
		// La pseudonymisation déjà active en base bloque l'activation seule de l'anonymisation.
		{map[string]any{"ip_anonymize": true}, http.StatusBadRequest},
		{map[string]any{"ip_anonymize": true, "ip_pseudonymize": false}, http.StatusNoContent},
	}
	for i, s := range steps {
		if rec := f.do(http.MethodPut, "/api/v1/logs/settings", "a", s.body); rec.Code != s.want {
			t.Fatalf("étape %d %v : status %d, attendu %d (%s)", i, s.body, rec.Code, s.want, rec.Body)
		}
	}
	if got := admindb.GetSetting(f.db, "logs.ip_anonymize", ""); got != "true" {
		t.Errorf("logs.ip_anonymize = %q", got)
	}
	if got := admindb.GetSetting(f.db, "logs.ip_pseudonymize", ""); got != "false" {
		t.Errorf("logs.ip_pseudonymize = %q", got)
	}
	if n := f.auditCount("logs_ip_pseudonymize"); n != 2 {
		t.Errorf("audit logs_ip_pseudonymize : %d entrées, attendu 2", n)
	}
}

func TestRevealIPAfterPseudonymizationDisabled(t *testing.T) {
	f := newRGPDFixture(t)
	if rec := f.do(http.MethodPut, "/api/v1/logs/settings", "a", map[string]any{"ip_pseudonymize": true}); rec.Code != http.StatusNoContent {
		t.Fatalf("activation : %d %s", rec.Code, rec.Body)
	}
	f.store.Write(logs.Entry{Status: 200, Domain: "a.test", IP: "203.0.113.0", RealIP: "203.0.113.42"})
	f.store.Write(logs.Entry{Status: 200, Domain: "a.test", IP: "198.51.100.7"})
	var pseudoID, plainID int64
	f.db.QueryRow(`SELECT id FROM logs WHERE ip_enc != ''`).Scan(&pseudoID)       //nolint:errcheck
	f.db.QueryRow(`SELECT id FROM logs WHERE ip = '198.51.100.7'`).Scan(&plainID) //nolint:errcheck
	if pseudoID == 0 || plainID == 0 {
		t.Fatalf("entrées non écrites : pseudo=%d plain=%d", pseudoID, plainID)
	}

	if rec := f.do(http.MethodPut, "/api/v1/logs/settings", "a", map[string]any{"ip_pseudonymize": false}); rec.Code != http.StatusNoContent {
		t.Fatalf("désactivation : %d %s", rec.Code, rec.Body)
	}

	cases := []struct {
		user string
		body map[string]any
		want int
	}{
		{"a", map[string]any{"entry_id": pseudoID, "reason": "réquisition"}, http.StatusForbidden},
		{"sa", map[string]any{"entry_id": pseudoID}, http.StatusBadRequest},
		{"sa", map[string]any{"entry_id": 999999, "reason": "réquisition"}, http.StatusNotFound},
		{"sa", map[string]any{"entry_id": plainID, "reason": "réquisition"}, http.StatusUnprocessableEntity},
		{"sa", map[string]any{"entry_id": pseudoID, "reason": "réquisition"}, http.StatusOK},
	}
	for _, c := range cases {
		rec := f.do(http.MethodPost, "/api/v1/logs/reveal-ip", c.user, c.body)
		if rec.Code != c.want {
			t.Fatalf("%s %v : status %d, attendu %d (%s)", c.user, c.body, rec.Code, c.want, rec.Body)
		}
		if c.want == http.StatusOK {
			var out struct{ IP string }
			json.Unmarshal(rec.Body.Bytes(), &out) //nolint:errcheck
			if out.IP != "203.0.113.42" {
				t.Fatalf("IP révélée %q", out.IP)
			}
		}
	}
	if n := f.auditCount("gdpr_reveal_ip"); n != 1 {
		t.Errorf("audit gdpr_reveal_ip : %d entrées, attendu 1", n)
	}
}

func TestDeleteByIPDoesNotRecordTheErasedIP(t *testing.T) {
	f := newRGPDFixture(t)
	f.store.SetPseudonymize(true)
	f.store.Write(logs.Entry{Status: 200, IP: "203.0.113.0", RealIP: "203.0.113.42"})
	f.store.Write(logs.Entry{Status: 200, IP: "198.51.100.0", RealIP: "198.51.100.9"})

	if rec := f.do(http.MethodDelete, "/api/v1/logs/by-ip/"+logs.PseudonymizedIP, "a", nil); rec.Code != http.StatusBadRequest {
		t.Fatalf("by-ip/[pseudonymisé] : status %d, attendu 400", rec.Code)
	}
	rec := f.do(http.MethodDelete, "/api/v1/logs/by-ip/203.0.113.42", "a", map[string]string{"reason": "Art. 17"})
	if rec.Code != http.StatusOK {
		t.Fatalf("by-ip : status %d %s", rec.Code, rec.Body)
	}
	var out struct{ Deleted int64 }
	json.Unmarshal(rec.Body.Bytes(), &out) //nolint:errcheck
	if out.Deleted != 1 {
		t.Fatalf("deleted = %d, attendu 1", out.Deleted)
	}
	var leaks int
	f.db.QueryRow(`SELECT (SELECT COUNT(*) FROM logs WHERE message LIKE '%203.0.113.42%')
		+ (SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%203.0.113.42%')`).Scan(&leaks) //nolint:errcheck
	if leaks != 0 {
		t.Fatalf("l'IP effacée réapparaît en clair dans %d ligne(s) de logs ou d'audit", leaks)
	}
	if n := f.auditCount("rgpd_erasure_ip"); n != 1 {
		t.Fatalf("audit rgpd_erasure_ip : %d entrées, attendu 1", n)
	}
}

func TestDeleteByIPErasesBansHistoryAndGeoCacheAndLiftsGatewayBans(t *testing.T) {
	f := newRGPDFixture(t)
	var lifted, erased []string
	f.h = adminauth.RequireJWT("secret")(&LogsHandler{Log: slog.Default(), Store: f.store, DB: f.db,
		OnUnban:   func(ip string) { lifted = append(lifted, ip) },
		OnEraseIP: func(ip string) { erased = append(erased, ip) }})
	for _, q := range []string{
		`INSERT INTO security_bans (id, ip) VALUES ('b1', '203.0.113.42')`,
		`INSERT INTO security_bans (id, ip) VALUES ('b2', '198.51.100.9')`,
		`INSERT INTO security_ban_history (ip, action) VALUES ('203.0.113.42', 'banned')`,
		`INSERT INTO security_ban_history (ip, action) VALUES ('203.0.113.42', 'unbanned')`,
		`INSERT INTO geoip_cache (ip, country_code, city) VALUES ('203.0.113.42', 'FR', 'Paris')`,
		`INSERT INTO geoip_cache (ip, country_code) VALUES ('198.51.100.9', 'DE')`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	rec := f.do(http.MethodDelete, "/api/v1/logs/by-ip/203.0.113.42", "a", map[string]string{"reason": "Art. 17"})
	if rec.Code != http.StatusOK {
		t.Fatalf("by-ip : status %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Bans       int64 `json:"bans_deleted"`
		BanHistory int64 `json:"ban_history_deleted"`
		GeoCache   int64 `json:"geoip_cache_deleted"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out) //nolint:errcheck
	if out.Bans != 1 || out.BanHistory != 2 || out.GeoCache != 1 {
		t.Fatalf("réponse %+v, attendu 1 ban, 2 événements, 1 entrée GeoIP", out)
	}
	if len(lifted) != 1 || lifted[0] != "203.0.113.42" {
		t.Fatalf("OnUnban appelé avec %v", lifted)
	}
	if len(erased) != 1 || erased[0] != "203.0.113.42" {
		t.Fatalf("OnEraseIP appelé avec %v", erased)
	}
	var left int
	f.db.QueryRow(`SELECT (SELECT COUNT(*) FROM security_bans WHERE ip = '203.0.113.42')
		+ (SELECT COUNT(*) FROM security_ban_history WHERE ip = '203.0.113.42')
		+ (SELECT COUNT(*) FROM geoip_cache WHERE ip = '203.0.113.42')`).Scan(&left) //nolint:errcheck
	if left != 0 {
		t.Fatalf("%d ligne(s) de l'IP effacée subsistent", left)
	}
	var others int
	f.db.QueryRow(`SELECT (SELECT COUNT(*) FROM security_bans) + (SELECT COUNT(*) FROM geoip_cache)`).Scan(&others) //nolint:errcheck
	if others != 2 {
		t.Fatalf("les données des autres IP ont été touchées : %d lignes, attendu 2", others)
	}
	var leaks int
	f.db.QueryRow(`SELECT (SELECT COUNT(*) FROM logs WHERE message LIKE '%203.0.113.42%')
		+ (SELECT COUNT(*) FROM audit_log WHERE detail LIKE '%203.0.113.42%')`).Scan(&leaks) //nolint:errcheck
	if leaks != 0 {
		t.Fatalf("l'IP effacée réapparaît en clair dans %d ligne(s) de logs ou d'audit", leaks)
	}
}

func TestLogsSettingsBanRetention(t *testing.T) {
	f := newRGPDFixture(t)
	if rec := f.do(http.MethodPut, "/api/v1/logs/settings", "a", map[string]any{"retention_ban_days": 180}); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(http.MethodPut, "/api/v1/logs/settings", "a", map[string]any{"retention_ban_days": -1}); rec.Code != http.StatusBadRequest {
		t.Fatalf("PUT négatif : %d, attendu 400", rec.Code)
	}
	rec := f.do(http.MethodGet, "/api/v1/logs/settings", "a", nil)
	var out struct {
		Ban int `json:"retention_ban_days"`
	}
	json.Unmarshal(rec.Body.Bytes(), &out) //nolint:errcheck
	if out.Ban != 180 || f.store.BanRetentionDays() != 180 {
		t.Fatalf("retention_ban_days = %d (store %d), attendu 180", out.Ban, f.store.BanRetentionDays())
	}
}

func TestSubjectExportByIPAndUser(t *testing.T) {
	f := newRGPDFixture(t)
	f.store.SetPseudonymize(true)
	f.store.Write(logs.Entry{Status: 200, Domain: "a.test", IP: "203.0.113.0", RealIP: "203.0.113.42", UserID: "a"})
	f.store.Write(logs.Entry{Status: 200, Domain: "b.test", IP: "198.51.100.0", RealIP: "198.51.100.9"})
	for _, q := range []string{
		`INSERT INTO security_bans (id, ip, reason, source) VALUES ('b1', '203.0.113.42', 'scan', 'fail2ban')`,
		`INSERT INTO security_ban_history (ip, action, source) VALUES ('203.0.113.42', 'banned', 'fail2ban')`,
		`INSERT INTO geoip_cache (ip, country_code, country_name, city) VALUES ('203.0.113.42', 'FR', 'France', 'Paris')`,
		`INSERT INTO audit_log (actor, action, resource, ip, user_id) VALUES ('a@t.local', 'login', 'session', '203.0.113.42', 'a')`,
		`INSERT INTO teams (id, name) VALUES ('t1', 'ops')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('t1', 'a')`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}

	if rec := f.do(http.MethodPost, "/api/v1/logs/subject-export", "a", map[string]string{}); rec.Code != http.StatusBadRequest {
		t.Fatalf("sans sujet : status %d, attendu 400", rec.Code)
	}
	if rec := f.do(http.MethodPost, "/api/v1/logs/subject-export", "a", map[string]string{"ip": "203.0.113.42", "user_id": "a"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("deux sujets : status %d, attendu 400", rec.Code)
	}
	if rec := f.do(http.MethodPost, "/api/v1/logs/subject-export", "a", map[string]string{"ip": "pas-une-ip"}); rec.Code != http.StatusBadRequest {
		t.Fatalf("IP invalide : status %d, attendu 400", rec.Code)
	}

	rec := f.do(http.MethodPost, "/api/v1/logs/subject-export", "a", map[string]string{"ip": "203.0.113.42", "reason": "demande de la personne"})
	if rec.Code != http.StatusOK {
		t.Fatalf("export IP : status %d %s", rec.Code, rec.Body)
	}
	if !bytes.Contains([]byte(rec.Header().Get("Content-Disposition")), []byte("attachment")) {
		t.Errorf("Content-Disposition = %q", rec.Header().Get("Content-Disposition"))
	}
	var ipOut struct {
		IP   string
		Logs []struct {
			IP     string
			Domain string
		}
		Bans       []struct{ Reason string }
		BanHistory []struct{ Action string } `json:"ban_history"`
		GeoIP      struct{ City string }     `json:"geoip"`
		Audit      []struct{ Action string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &ipOut); err != nil {
		t.Fatal(err)
	}
	if len(ipOut.Logs) != 1 || ipOut.Logs[0].Domain != "a.test" || ipOut.Logs[0].IP != "203.0.113.42" {
		t.Fatalf("logs de l'IP : %+v (les entrées pseudonymisées doivent être retrouvées, les autres IP exclues)", ipOut.Logs)
	}
	if len(ipOut.Bans) != 1 || len(ipOut.BanHistory) != 1 || ipOut.GeoIP.City != "Paris" || len(ipOut.Audit) != 1 {
		t.Fatalf("export IP incomplet : %s", rec.Body)
	}

	rec = f.do(http.MethodPost, "/api/v1/logs/subject-export", "a", map[string]string{"user_id": "a"})
	if rec.Code != http.StatusOK {
		t.Fatalf("export user : status %d %s", rec.Code, rec.Body)
	}
	var userOut struct {
		Account struct {
			Email string
			Teams []string
		}
		Logs  []struct{ Domain string }
		Audit []struct{ Action string }
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &userOut); err != nil {
		t.Fatal(err)
	}
	if userOut.Account.Email != "a@t.local" || len(userOut.Account.Teams) != 1 || len(userOut.Logs) != 1 || len(userOut.Audit) < 2 {
		t.Fatalf("export compte (attendu : profil, 1 log, au moins l'audit de connexion et celui de l'export IP) : %s", rec.Body)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("password")) {
		t.Errorf("l'export d'un compte ne doit pas contenir de mot de passe : %s", rec.Body)
	}

	if n := f.auditCount("rgpd_export_ip"); n != 1 {
		t.Errorf("audit rgpd_export_ip : %d, attendu 1", n)
	}
	if n := f.auditCount("rgpd_export_user"); n != 1 {
		t.Errorf("audit rgpd_export_user : %d, attendu 1", n)
	}
	var leaks int
	f.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action LIKE 'rgpd_export%' AND detail LIKE '%203.0.113.42%'`).Scan(&leaks) //nolint:errcheck
	if leaks != 0 {
		t.Errorf("l'IP exportée apparaît en clair dans l'audit de l'export")
	}

	// L'effacement vide aussi l'IP des entrées d'audit sans supprimer l'entrée.
	if rec := f.do(http.MethodDelete, "/api/v1/logs/by-ip/203.0.113.42", "a", nil); rec.Code != http.StatusOK {
		t.Fatalf("by-ip : %d %s", rec.Code, rec.Body)
	}
	var auditIP string
	f.db.QueryRow(`SELECT ip FROM audit_log WHERE action = 'login'`).Scan(&auditIP) //nolint:errcheck
	var rows int
	f.db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'login'`).Scan(&rows) //nolint:errcheck
	if auditIP != "" || rows != 1 {
		t.Errorf("audit après effacement : ip=%q lignes=%d, attendu ip vide et ligne conservée", auditIP, rows)
	}
}
