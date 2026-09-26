// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/security"
)

func TestListBansEdgeFilter(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "bans.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, s := range []string{
		`INSERT INTO security_bans (id, ip, source, edge_name) VALUES ('a', '1.1.1.1', 'threat', 'paris-01')`,
		`INSERT INTO security_bans (id, ip, source, edge_name) VALUES ('b', '2.2.2.2', 'threat', 'lyon-02')`,
		`INSERT INTO security_bans (id, ip, source) VALUES ('c', '3.3.3.3', 'native')`,
		`INSERT INTO security_bans (id, ip, source, expires_at) VALUES ('d', '4.4.4.4', 'native', '2000-01-01 00:00:00')`,
	} {
		if _, err := db.Exec(s); err != nil {
			t.Fatal(err)
		}
	}
	h := &api.SecurityHandler{DB: db}

	ips := func(query string) map[string]bool {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/bans"+query, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s: status %d", query, rec.Code)
		}
		var out []security.Ban
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		got := map[string]bool{}
		for _, b := range out {
			got[b.IP] = true
		}
		return got
	}

	if got := ips("?active=true&edge=paris-01"); len(got) != 2 || !got["1.1.1.1"] || !got["3.3.3.3"] {
		t.Errorf("edge=paris-01 doit renvoyer ses bans et les bans globaux, reçu %v", got)
	}
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name) VALUES ('tok-1', 'secret', 'edge', 'paris-01')`); err != nil {
		t.Fatal(err)
	}
	if got := ips("?active=true&edge=tok-1"); len(got) != 2 || !got["1.1.1.1"] || !got["3.3.3.3"] {
		t.Errorf("edge=<id token> doit être résolu en nom de nœud, reçu %v", got)
	}
	if got := ips("?active=true"); len(got) != 3 {
		t.Errorf("sans filtre : 3 bans actifs attendus, reçu %v", got)
	}
	if got := ips("?active=false"); len(got) != 1 || !got["4.4.4.4"] {
		t.Errorf("active=false ne doit renvoyer que les expirés, reçu %v", got)
	}
}

func TestIntelKPIsEdgeFilter(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "intel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, ip := range []string{"1.1.1.1", "1.1.1.1", "1.1.1.1", "2.2.2.2"} {
		if _, err := db.Exec(`INSERT INTO security_ban_history (ip, action, edge_name) VALUES (?, 'banned', 'paris-01')`, ip); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO security_ban_history (ip, action, edge_name) VALUES ('9.9.9.9', 'banned', 'lyon-02')`); err != nil {
		t.Fatal(err)
	}
	h := &api.SecurityHandler{DB: db}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/bans/intel/kpis?edge=paris-01", nil))
	var kpis struct {
		HistoryTotal int `json:"history_total"`
		Recurring    int `json:"recurring_ips"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &kpis); err != nil {
		t.Fatal(err)
	}
	if kpis.HistoryTotal != 4 || kpis.Recurring != 1 {
		t.Errorf("history_total=4 et recurring_ips=1 attendus, reçu %+v", kpis)
	}
}
