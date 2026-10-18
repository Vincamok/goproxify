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
	var lifted []string
	f.h = adminauth.RequireJWT("secret")(&LogsHandler{Log: slog.Default(), Store: f.store, DB: f.db,
		OnUnban: func(ip string) { lifted = append(lifted, ip) }})
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
