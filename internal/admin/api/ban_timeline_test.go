// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/sqltime"
)

func TestBanTimelinesKeepTheWindowsFirstDay(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// created_at au format de CURRENT_TIMESTAMP, comme en production. Les bans d'il y a 59 min tombent
	// le même jour UTC que le début d'une fenêtre d'une heure : une borne RFC3339 les écartait ('T' > ' ').
	now := time.Now()
	for age, n := range map[time.Duration]int{59 * time.Minute: 3, time.Minute: 1, 2 * time.Hour: 1} {
		for i := 0; i < n; i++ {
			if _, err := db.Exec(`INSERT INTO security_ban_history (ip, action, source, created_at) VALUES ('203.0.113.9', 'banned', 'fail2ban', ?)`,
				sqltime.Format(now.Add(-age))); err != nil {
				t.Fatal(err)
			}
		}
	}
	total := func(h http.Handler, path string) int {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : status %d %s", path, rec.Code, rec.Body)
		}
		var pts []struct{ Count int }
		if err := json.Unmarshal(rec.Body.Bytes(), &pts); err != nil {
			t.Fatal(err)
		}
		n := 0
		for _, p := range pts {
			n += p.Count
		}
		return n
	}

	if n := total(&SecurityHandler{DB: db}, "/api/v1/security/bans/intel/timeline?hours=1"); n != 4 {
		t.Errorf("intel/timeline sur 1 h : %d bans, attendu 4", n)
	}
	q := url.Values{
		"from": {now.Add(-time.Hour).UTC().Format(time.RFC3339)},
		"to":   {now.Add(-30 * time.Minute).UTC().Format(time.RFC3339)},
	}
	if n := total(&PrismHandler{DB: db}, "/api/v1/prism/bans/timeline?"+q.Encode()); n != 3 {
		t.Errorf("prism/bans/timeline de -1 h à -30 min : %d bans, attendu 3", n)
	}
}
