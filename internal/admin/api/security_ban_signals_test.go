// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// Un ban automatique garde son explication dans la liste des bans et dans la trace de l'IP (ban en cours et historique) ;
// les bans sans signaux n'en portent pas.
func TestBanSignalsAreExposedByTheBanListAndTheIPTrace(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	signals := []router.BanSignal{{Name: "custom_path", Points: 6, Value: "/wp-login.php"}, {Name: "error4xx", Points: 2.5, Value: "404 /x"}}
	enc := security.EncodeBanSignals(signals)
	exec := func(q string, args ...any) {
		t.Helper()
		if _, err := db.Exec(q, args...); err != nil {
			t.Fatal(err)
		}
	}
	exec(`INSERT INTO security_bans (id, ip, reason, source, edge_name, signals) VALUES ('threat-203.0.113.5', '203.0.113.5', 'threat: score cumulé', 'threat', 'paris', ?)`, enc)
	exec(`INSERT INTO security_bans (id, ip, reason, source) VALUES ('n1', '203.0.113.6', 'manuel', 'native')`)
	exec(`INSERT INTO security_ban_history (ip, action, reason, source, signals, created_at) VALUES ('203.0.113.5', 'banned', 'threat: score cumulé', 'threat', ?, ?)`,
		enc, sqltime.Format(time.Now().Add(-time.Hour)))
	h := &SecurityHandler{DB: db}

	get := func(path string, v any) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, path, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : %d %s", path, rec.Code, rec.Body)
		}
		if err := json.Unmarshal(rec.Body.Bytes(), v); err != nil {
			t.Fatal(err)
		}
	}

	var bans []security.Ban
	get("/api/v1/security/bans?active=true", &bans)
	if len(bans) != 2 {
		t.Fatalf("bans : %+v", bans)
	}
	for _, b := range bans {
		switch b.IP {
		case "203.0.113.5":
			if len(b.Signals) != 2 || b.Signals[0] != signals[0] || b.Signals[1] != signals[1] {
				t.Errorf("signaux de la liste : %+v", b.Signals)
			}
		case "203.0.113.6":
			if len(b.Signals) != 0 {
				t.Errorf("un ban manuel n'a pas de signaux : %+v", b.Signals)
			}
		}
	}

	var trace struct {
		Summary struct {
			ActiveBans []traceBan `json:"active_bans"`
		} `json:"summary"`
		Steps []TraceStep `json:"steps"`
	}
	get("/api/v1/security/ip-trace?target=203.0.113.5", &trace)
	if len(trace.Summary.ActiveBans) != 1 || len(trace.Summary.ActiveBans[0].Signals) != 2 {
		t.Errorf("ban en cours de la trace : %+v", trace.Summary.ActiveBans)
	}
	var found bool
	for _, s := range trace.Steps {
		if s.Kind == "ban" && len(s.Signals) == 2 && s.Signals[0] == signals[0] {
			found = true
		}
	}
	if !found {
		t.Errorf("l'étape de ban de la trace doit porter ses signaux : %+v", trace.Steps)
	}
}

func TestEncodeBanSignalsBoundsWhatTheNetworkSends(t *testing.T) {
	var many []router.BanSignal
	for i := 0; i < 40; i++ {
		many = append(many, router.BanSignal{Name: "s", Points: 1})
	}
	if got := security.DecodeBanSignals(security.EncodeBanSignals(many)); len(got) != 16 {
		t.Errorf("%d signaux conservés, attendu 16", len(got))
	}
	long := make([]byte, 5000)
	for i := range long {
		long[i] = 'a'
	}
	got := security.DecodeBanSignals(security.EncodeBanSignals([]router.BanSignal{{Name: string(long), Points: 1e12, Value: string(long)}}))
	if len(got) != 1 || len(got[0].Name) != 40 || len(got[0].Value) != 200 || got[0].Points != 1e6 {
		t.Errorf("bornes : %+v", got)
	}
	if security.EncodeBanSignals(nil) != "" || security.DecodeBanSignals("pas du json") != nil {
		t.Error("vide et illisible doivent donner rien")
	}
}
