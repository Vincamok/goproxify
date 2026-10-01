// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/security"
)

func TestActiveBanViewsIgnoreBansExpiredAMinuteAgo(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	past, future := time.Now().Add(-time.Minute).UTC(), time.Now().Add(time.Hour).UTC()
	bans := map[string]string{
		"203.0.113.10": past.Format(time.RFC3339),               // passerelle
		"203.0.113.11": past.Format("2006-01-02T15:04:05.000Z"), // UI (toISOString)
		"203.0.113.12": future.Format(time.RFC3339),             // actif
		"203.0.113.13": future.Format("2006-01-02 15:04:05"),    // actif
	}
	for ip, exp := range bans {
		if _, err := db.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES (?, ?, 'threat', ?)`, ip, ip, exp); err != nil {
			t.Fatal(err)
		}
	}
	get := func(h http.Handler, path string, out any) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : status %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), out); err != nil {
			t.Fatal(err)
		}
	}
	listed := func(query string) map[string]bool {
		var out []security.Ban
		get(&SecurityHandler{DB: db}, "/api/v1/security/bans"+query, &out)
		got := map[string]bool{}
		for _, b := range out {
			got[b.IP] = true
		}
		return got
	}

	if got := listed("?active=true"); len(got) != 2 || !got["203.0.113.12"] || !got["203.0.113.13"] {
		t.Errorf("active=true : %v, attendu les 2 bans non expirés", got)
	}
	if got := listed("?active=false"); len(got) != 2 || !got["203.0.113.10"] || !got["203.0.113.11"] {
		t.Errorf("active=false : %v, attendu les 2 bans expirés depuis 1 min", got)
	}
	var countries []struct{ Count int }
	get(&SecurityHandler{DB: db}, "/api/v1/security/bans/countries", &countries)
	var bySource []struct{ Count int }
	get(&PrismHandler{DB: db}, "/api/v1/prism/bans/by-source", &bySource)
	for name, rows := range map[string][]struct{ Count int }{"bans/countries": countries, "prism/bans/by-source": bySource} {
		n := 0
		for _, r := range rows {
			n += r.Count
		}
		if n != 2 {
			t.Errorf("%s : %d bans actifs, attendu 2", name, n)
		}
	}
	var live topologyLive
	get(&NodesHandler{DB: db, Log: slog.Default()}, "/api/v1/nodes/live", &live)
	if live.BansActive != 2 {
		t.Errorf("nodes/live : %d bans actifs, attendu 2", live.BansActive)
	}
}
