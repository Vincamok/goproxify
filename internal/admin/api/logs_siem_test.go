// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

type fakeSIEMControl struct {
	pushes int
	status []siemcfg.NodeStatus
}

func (f *fakeSIEMControl) PushSIEMConfig(context.Context)   { f.pushes++ }
func (f *fakeSIEMControl) SIEMStatus() []siemcfg.NodeStatus { return f.status }

func TestLogsSIEMConfigAPI(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctl := &fakeSIEMControl{status: []siemcfg.NodeStatus{{NodeName: "gw-a", Destinations: []siem.DestinationStatus{{ID: "x", Name: "Splunk", State: "ok"}}}}}
	h := &LogsHandler{DB: db, SIEM: ctl}
	do := func(method, path, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, path, strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}

	rec := do(http.MethodGet, "/api/v1/logs/siem", "")
	var got siem.Config
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &got) != nil || got.Enabled || len(got.Destinations) != 0 {
		t.Fatalf("configuration vide : %d %s", rec.Code, rec.Body)
	}

	put := `{"enabled":true,"destinations":[{"name":"Splunk","type":"http","address":"https://splunk.example/in","headers":{"Authorization":"Bearer s3cret"},"min_level":"warn"}]}`
	rec = do(http.MethodPut, "/api/v1/logs/siem", put)
	if rec.Code != 200 {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatal("la réponse du PUT contient le jeton")
	}
	var saved siem.Config
	_ = json.Unmarshal(rec.Body.Bytes(), &saved)
	if len(saved.Destinations) != 1 || saved.Destinations[0].ID == "" || saved.Destinations[0].Headers["Authorization"] != siemcfg.Masked {
		t.Fatalf("réponse : %+v", saved)
	}
	if ctl.pushes != 1 {
		t.Errorf("%d poussées vers les passerelles", ctl.pushes)
	}
	if stored := siemcfg.Load(db); stored.Destinations[0].Headers["Authorization"] != "Bearer s3cret" || stored.Destinations[0].MinLevel != "warn" {
		t.Fatalf("configuration enregistrée : %+v", stored)
	}
	var audits int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='logs_siem_config' AND detail NOT LIKE '%s3cret%'`).Scan(&audits)
	if audits != 1 {
		t.Errorf("%d entrées d'audit sans secret", audits)
	}

	// La lecture masque ; renvoyer la lecture telle quelle garde le jeton.
	rec = do(http.MethodGet, "/api/v1/logs/siem", "")
	if strings.Contains(rec.Body.String(), "s3cret") {
		t.Fatal("la lecture contient le jeton")
	}
	if rec = do(http.MethodPut, "/api/v1/logs/siem", rec.Body.String()); rec.Code != 200 {
		t.Fatalf("PUT de la lecture : %d %s", rec.Code, rec.Body)
	}
	if siemcfg.Load(db).Destinations[0].Headers["Authorization"] != "Bearer s3cret" {
		t.Fatal("le jeton a été écrasé par sa valeur masquée")
	}

	// Une configuration invalide est refusée sans rien changer.
	rec = do(http.MethodPut, "/api/v1/logs/siem", `{"enabled":true,"destinations":[{"name":"x","type":"kafka","address":"h:1"}]}`)
	if rec.Code != http.StatusBadRequest || ctl.pushes != 2 {
		t.Fatalf("configuration invalide : %d (%d poussées)", rec.Code, ctl.pushes)
	}
	if rec = do(http.MethodPut, "/api/v1/logs/siem", `pas du json`); rec.Code != http.StatusBadRequest {
		t.Fatalf("JSON invalide : %d", rec.Code)
	}

	rec = do(http.MethodGet, "/api/v1/logs/siem/status", "")
	var st struct {
		Nodes []siemcfg.NodeStatus `json:"nodes"`
	}
	if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &st) != nil || len(st.Nodes) != 1 || st.Nodes[0].Destinations[0].Name != "Splunk" {
		t.Fatalf("état : %d %s", rec.Code, rec.Body)
	}
}
