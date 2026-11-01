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
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func TestCalibrateIsRunByEachGatewayOnItsOwnTraffic(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "cal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 30; i++ {
		gw.Add(logstore.Entry{Ts: time.Now().UTC().Add(-time.Duration(30-i) * time.Minute), Component: "edge", Domain: "a.test", Method: "GET", Path: "/", Status: 200, IP: "9.9.9.9"})
	}
	// La configuration d'Ephor de la portée donne les heures d'observation d'un créneau.
	if _, err := db.Exec(`INSERT INTO settings (key, value) VALUES ('threat_engine_config', ?)`, `{"enabled":true,"seasonal":{"mode":"detect","min_hours":0.5},"enumeration":{"window":"15m"}}`); err != nil {
		t.Fatal(err)
	}
	h := &api.SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}

	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/calibrate", strings.NewReader(`{"hours":2}`)))
	if rec.Code != http.StatusOK {
		t.Fatalf("POST calibrate : %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Window   int `json:"window_hours"`
		Gateways []struct {
			Name   string `json:"node_name"`
			Report struct {
				Events   int `json:"events"`
				Seasonal struct {
					Routes     int               `json:"routes"`
					Candidates []json.RawMessage `json:"candidates"`
				} `json:"seasonal"`
			} `json:"report"`
		} `json:"gateways"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Window != 2 || len(out.Gateways) != 1 || out.Gateways[0].Report.Events != 30 || out.Gateways[0].Report.Seasonal.Routes != 1 || len(out.Gateways[0].Report.Seasonal.Candidates) != 36 {
		t.Fatalf("une passerelle, ses 30 accès, la grille entière : %s", rec.Body.String())
	}
	if got := gw.LastCalibrate; got.Hours != 2 || got.MinHours != 0.5 || got.EnumWindowSeconds != 900 {
		t.Fatalf("la passerelle doit recevoir la fenêtre et les réglages de la configuration d'Ephor : %+v", got)
	}

	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/security/threat-config/calibrate", strings.NewReader(`{"hours":9999}`)))
	if rec.Code != http.StatusOK || gw.LastCalibrate.Hours != api.CalibMaxHours {
		t.Fatalf("la fenêtre est bornée à %d h : %d, reçu %d", api.CalibMaxHours, rec.Code, gw.LastCalibrate.Hours)
	}
}
