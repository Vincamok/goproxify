// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"database/sql"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func openBansDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return db
}

func serveBans(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func banExpiry(t *testing.T, db *sql.DB, id string) sql.NullString {
	t.Helper()
	var exp sql.NullString
	if err := db.QueryRow(`SELECT expires_at FROM security_bans WHERE id=?`, id).Scan(&exp); err != nil {
		t.Fatal(err)
	}
	return exp
}

func TestCreateBanNormalizesExpiresAt(t *testing.T) {
	db := openBansDB(t)
	h := &api.SecurityHandler{DB: db}

	for body, want := range map[string]sql.NullString{
		`{"ip":"203.0.113.1","expires_at":"2026-12-31T23:59:59.000Z"}`:    {String: "2026-12-31T23:59:59Z", Valid: true},
		`{"ip":"203.0.113.2","expires_at":"2027-01-01T01:00:00+02:00"}`:   {String: "2026-12-31T23:00:00Z", Valid: true},
		`{"ip":"203.0.113.3","expires_at":""}`:                            {},
		`{"ip":"203.0.113.4"}`:                                            {},
		`{"ip":"203.0.113.5","expires_at":"2026-12-31T23:59:59.123456Z"}`: {String: "2026-12-31T23:59:59Z", Valid: true},
	} {
		rec := serveBans(h, http.MethodPost, "/api/v1/security/bans", body)
		if rec.Code != http.StatusCreated {
			t.Fatalf("%s : status %d %s", body, rec.Code, rec.Body)
		}
		var res struct{ ID string }
		if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
			t.Fatal(err)
		}
		if got := banExpiry(t, db, res.ID); got != want {
			t.Errorf("%s : expires_at=%v, attendu %v", body, got, want)
		}
	}

	for _, exp := range []string{"demain", "2026-12-31 23:59:59", "2026-12-31", "1h"} {
		rec := serveBans(h, http.MethodPost, "/api/v1/security/bans", `{"ip":"203.0.113.9","expires_at":"`+exp+`"}`)
		if rec.Code != http.StatusBadRequest {
			t.Errorf("expires_at=%q : status %d, attendu 400", exp, rec.Code)
		}
	}
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE ip='203.0.113.9'`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 0 {
		t.Errorf("%d ban(s) créé(s) avec une expiration invalide", n)
	}
}

func TestUpdateBanValidatesExpiresAt(t *testing.T) {
	db := openBansDB(t)
	if _, err := db.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES ('b1', '203.0.113.1', 'native', '2026-12-31T23:59:59Z')`); err != nil {
		t.Fatal(err)
	}
	h := &api.SecurityHandler{DB: db}
	patch := func(body string) int {
		return serveBans(h, http.MethodPatch, "/api/v1/security/bans/b1", body).Code
	}

	if code := patch(`{"expires_at":"lundi"}`); code != http.StatusBadRequest {
		t.Errorf("expires_at illisible : status %d, attendu 400", code)
	}
	if got := banExpiry(t, db, "b1"); got.String != "2026-12-31T23:59:59Z" {
		t.Errorf("expires_at modifié par une requête rejetée : %v", got)
	}

	if code := patch(`{"expires_at":"2027-01-02T12:00:00.000+01:00"}`); code != http.StatusNoContent {
		t.Fatalf("status %d, attendu 204", code)
	}
	if got := banExpiry(t, db, "b1"); got.String != "2027-01-02T11:00:00Z" {
		t.Errorf("expires_at=%v, attendu 2027-01-02T11:00:00Z", got)
	}

	if code := patch(`{"expires_at":""}`); code != http.StatusNoContent {
		t.Fatalf("status %d, attendu 204", code)
	}
	if got := banExpiry(t, db, "b1"); got.Valid {
		t.Errorf("expires_at=%v, attendu NULL (ban permanent)", got)
	}
}
