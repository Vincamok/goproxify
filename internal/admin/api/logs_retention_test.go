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
	"github.com/vincamok/goproxify/internal/admin/logs"
)

type fakeRetentionControl struct {
	pushes int
	info   []EdgeLogInfo
}

func (f *fakeRetentionControl) PushLogRetention(context.Context) { f.pushes++ }
func (f *fakeRetentionControl) LogInfo() []EdgeLogInfo           { return f.info }

func TestEdgeRetentionSettingsAreValidatedSavedAuditedAndPushed(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	ctl := &fakeRetentionControl{info: []EdgeLogInfo{{NodeName: "gw-b", AccessDays: 200, SystemDays: 60}, {NodeName: "gw-a", AccessDays: 365, SystemDays: 90}}}
	h := &LogsHandler{DB: db, Store: logs.New(db), Retention: ctl}
	do := func(method, body string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/api/v1/logs/settings", strings.NewReader(body))
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, req)
		return rec
	}
	view := func() (v struct {
		EdgeRetention struct {
			Configured bool                             `json:"configured"`
			AccessDays int                              `json:"access_days"`
			SystemDays int                              `json:"system_days"`
			Nodes      map[string]EdgeRetentionOverride `json:"nodes"`
			Edges      []EdgeLogInfo                    `json:"edges"`
			Defaults   map[string]int                   `json:"defaults"`
		} `json:"edge_retention"`
	}) {
		rec := do(http.MethodGet, "")
		if rec.Code != 200 || json.Unmarshal(rec.Body.Bytes(), &v) != nil {
			t.Fatalf("GET : %d %s", rec.Code, rec.Body)
		}
		return v
	}

	v := view()
	if v.EdgeRetention.Configured || v.EdgeRetention.AccessDays != 365 || v.EdgeRetention.SystemDays != 90 || v.EdgeRetention.Defaults["access_days"] != 365 {
		t.Fatalf("avant réglage : %+v", v.EdgeRetention)
	}
	if e := v.EdgeRetention.Edges; len(e) != 2 || e[0].NodeName != "gw-a" || e[1].AccessDays != 200 {
		t.Errorf("rétention annoncée : %+v", e)
	}

	for name, body := range map[string]string{
		"zéro":      `{"edge_retention":{"access_days":0,"system_days":90}}`,
		"trop long": `{"edge_retention":{"access_days":4000,"system_days":90}}`,
		"exception": `{"edge_retention":{"access_days":30,"system_days":30,"nodes":{"gw-a":{"access_days":99999}}}}`,
		"nom vide":  `{"edge_retention":{"access_days":30,"system_days":30,"nodes":{"":{"access_days":5}}}}`,
	} {
		if rec := do(http.MethodPut, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d", name, rec.Code)
		}
	}
	if ctl.pushes != 0 || view().EdgeRetention.Configured {
		t.Fatal("un réglage invalide a été enregistré ou poussé")
	}

	body := `{"edge_retention":{"access_days":180,"system_days":45,"nodes":{"gw-b":{"access_days":30},"gw-c":{}}}}`
	if rec := do(http.MethodPut, body); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body)
	}
	v = view()
	if !v.EdgeRetention.Configured || v.EdgeRetention.AccessDays != 180 || v.EdgeRetention.SystemDays != 45 || ctl.pushes != 1 {
		t.Fatalf("après réglage : %+v (%d poussées)", v.EdgeRetention, ctl.pushes)
	}
	if n := v.EdgeRetention.Nodes; len(n) != 1 || n["gw-b"].AccessDays != 30 {
		t.Errorf("exceptions : %v (une exception vide doit disparaître)", n)
	}
	r, _ := LoadEdgeRetention(db)
	if a, s := r.For("gw-b"); a != 30 || s != 45 {
		t.Errorf("gw-b : %d / %d, attendu 30 / 45 (l'exception ne porte que sur les accès)", a, s)
	}
	if a, s := r.For("gw-z"); a != 180 || s != 45 {
		t.Errorf("gw-z : %d / %d", a, s)
	}
	var audits int
	_ = db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='logs_edge_retention'`).Scan(&audits)
	if audits != 1 {
		t.Errorf("%d entrées d'audit", audits)
	}
	// Un PUT sans edge_retention ne touche pas à la rétention des passerelles.
	if rec := do(http.MethodPut, `{"retention_access_days":60}`); rec.Code != http.StatusNoContent || ctl.pushes != 1 {
		t.Errorf("PUT sans edge_retention : %d, %d poussées", rec.Code, ctl.pushes)
	}
}
