// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestIPProfilesExposeRefreshState(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO ip_profiles (id, name, mode, last_error, consecutive_failures, next_attempt_at)
		VALUES ('p', 'p', 'deny', 'HTTP 503', 3, '2030-01-01 00:00:00')`); err != nil {
		t.Fatal(err)
	}
	h := &api.IPProfilesHandler{DB: db}

	for _, path := range []string{"/api/v1/ip-profiles", "/api/v1/ip-profiles/p"} {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: HTTP %d", path, rec.Code)
		}
		var got struct {
			LastError           string `json:"last_error"`
			ConsecutiveFailures int    `json:"consecutive_failures"`
			NextAttemptAt       string `json:"next_attempt_at"`
		}
		body := rec.Body.Bytes()
		if body[0] == '[' {
			var list []struct {
				LastError           string `json:"last_error"`
				ConsecutiveFailures int    `json:"consecutive_failures"`
				NextAttemptAt       string `json:"next_attempt_at"`
			}
			if err := json.Unmarshal(body, &list); err != nil || len(list) != 1 {
				t.Fatalf("%s: %v %s", path, err, body)
			}
			got = list[0]
		} else if err := json.Unmarshal(body, &got); err != nil {
			t.Fatal(err)
		}
		if got.LastError != "HTTP 503" || got.ConsecutiveFailures != 3 || got.NextAttemptAt == "" {
			t.Fatalf("%s: état absent: %+v", path, got)
		}
	}
}

func TestIPProfilesManualCIDRs(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &api.IPProfilesHandler{DB: db}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
		return rec
	}

	for name, body := range map[string]string{
		"cidr invalide":    `{"name":"a","cidrs":["pas-une-ip"]}`,
		"feed et cidrs":    `{"name":"b","feed_urls":["https://x"],"cidrs":["203.0.113.0/24"]}`,
		"ni feed ni cidrs": `{"name":"c"}`,
		"mode inconnu":     `{"name":"d","mode":"x","cidrs":["203.0.113.1"]}`,
	} {
		if rec := do(http.MethodPost, "/api/v1/ip-profiles", body); rec.Code != http.StatusBadRequest {
			t.Fatalf("%s: HTTP %d, attendu 400", name, rec.Code)
		}
	}

	rec := do(http.MethodPost, "/api/v1/ip-profiles", `{"name":"bureau","mode":"allow","enabled":true,"cidrs":["203.0.113.5","203.0.113.4/32","198.51.100.0/24"]}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création: HTTP %d %s", rec.Code, rec.Body)
	}
	var created struct{ ID string }
	json.Unmarshal(rec.Body.Bytes(), &created) //nolint:errcheck

	// La bascule actif/inactif n'envoie pas de cidrs : la liste doit survivre.
	if rec := do(http.MethodPut, "/api/v1/ip-profiles/"+created.ID, `{"name":"bureau","mode":"allow","enabled":false}`); rec.Code != http.StatusNoContent {
		t.Fatalf("toggle: HTTP %d", rec.Code)
	}
	var cidrs string
	db.QueryRow(`SELECT cidrs FROM ip_profiles WHERE id=?`, created.ID).Scan(&cidrs) //nolint:errcheck
	if cidrs != `["198.51.100.0/24","203.0.113.4/31"]` {
		t.Fatalf("liste manuelle perdue ou mal agrégée: %q", cidrs)
	}
	var feeds string
	db.QueryRow(`SELECT feed_urls FROM ip_profiles WHERE id=?`, created.ID).Scan(&feeds) //nolint:errcheck
	if feeds != "[]" {
		t.Fatalf("feed_urls d'un profil manuel = %q, attendu []", feeds)
	}
}
