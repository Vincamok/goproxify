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
	"github.com/vincamok/goproxify/internal/admin/logs"
)

func TestNiceCeil(t *testing.T) {
	for in, want := range map[float64]float64{0.4: 0.5, 1: 1, 1.1: 2, 20: 20, 21: 50, 137: 200, 480: 500, 501: 1000, 12000: 20000} {
		if got := niceCeil(in); got != want {
			t.Errorf("niceCeil(%v) = %v, attendu %v", in, got, want)
		}
	}
}

func TestPercentile(t *testing.T) {
	v := []float64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}
	if percentile(v, 0.5) != 5 || percentile(v, 0.99) != 10 || percentile(v, 0) != 1 || percentile(nil, 0.5) != 0 {
		t.Fatal("percentiles")
	}
}

func TestThresholdSuggestionsComeFromTheMinuteAggregates(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	insert := func(node string, at time.Time, status, requests int) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO logs_minute (minute, node_name, domain, status, requests) VALUES (?, ?, 'a.test', ?, ?)`,
			logs.MinuteKey(at), node, status, requests); err != nil {
			t.Fatal(err)
		}
	}
	now := time.Now().UTC()
	// Paris : deux jours de trafic régulier autour de 1 200 requêtes par minute (20 req/s), avec une pointe à 6 000.
	for m := 0; m < 2*24*60; m++ {
		at := now.Add(-time.Duration(m+10) * time.Minute)
		insert("paris", at, 200, 1100+m%100)
		if m%10 == 0 {
			insert("paris", at, 404, 50)
		}
	}
	insert("paris", now.Add(-30*time.Minute), 204, 6000)
	// Lyon : une heure de trafic seulement.
	for m := 0; m < 60; m++ {
		insert("lyon", now.Add(-time.Duration(m+10)*time.Minute), 200, 600)
	}
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('threat_engine_config', '{"enabled":true,"global_rps":100}')`); err != nil {
		t.Fatal(err)
	}

	h := &SecurityHandler{DB: db}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/threat-config/suggestions?days=7", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("%d %s", rec.Code, rec.Body)
	}
	var res struct {
		Suggestions []ThresholdSuggestion `json:"suggestions"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	by := map[string]ThresholdSuggestion{}
	for _, s := range res.Suggestions {
		by[s.NodeName] = s
	}
	paris, lyon := by["paris"], by["lyon"]
	if !paris.Ready || paris.CurrentGlobalRPS != 100 || paris.RPSMax < 99 || paris.RPSMedian < 18 || paris.RPSMedian > 22 {
		t.Fatalf("Paris : %+v", paris)
	}
	if paris.SuggestedRPS < paris.RPS999*suggestBurstFactor || paris.SuggestedRPS > paris.RPS999*suggestBurstFactor*2.5 {
		t.Fatalf("Paris : limite %v hors de 4 × p99,9 (%v) arrondie au palier", paris.SuggestedRPS, paris.RPS999)
	}
	if paris.ErrorShare <= 0 || paris.ErrorShare > 5 {
		t.Fatalf("Paris : part d'erreurs %v", paris.ErrorShare)
	}
	if lyon.Ready || lyon.SuggestedRPS != 0 || lyon.Why == "" {
		t.Fatalf("Lyon n'a pas assez de trafic pour qu'on propose quoi que ce soit : %+v", lyon)
	}
}

func TestThresholdSuggestionsWithoutAnyData(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	out, err := SuggestEphorThresholds(t.Context(), db, "threat_engine_config", 0)
	if err != nil || len(out) != 0 {
		t.Fatalf("%v %+v", err, out)
	}
}
