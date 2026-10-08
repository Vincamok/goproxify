// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func newRuleHandlers(t *testing.T) (*RulesEngineHandler, *SchedulerHandler) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "rules.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	log := slog.New(slog.NewTextHandler(io.Discard, nil))
	return &RulesEngineHandler{DB: db, Log: log}, &SchedulerHandler{DB: db, Log: log}
}

func ruleCall(h http.Handler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func ruleJSON(action string) string {
	return `{"name":"r","enabled":true,"condition":{"type":"ban_spike","ban_count":5,"ban_window":"5m"},"action":` + action + `,"cooldown_sec":60}`
}

// Une action invalide est refusée à l'enregistrement : avant, elle n'échouait qu'au déclenchement, et une
// durée de ban illisible donnait un ban permanent.
func TestRules_ActionIsValidatedOnCreateAndUpdate(t *testing.T) {
	h, _ := newRuleHandlers(t)
	for name, action := range map[string]string{
		"type inconnu":     `{"type":"explode"}`,
		"type absent":      `{}`,
		"durée illisible":  `{"type":"ban_ip","ban_duration":"une heure"}`,
		"webhook sans URL": `{"type":"webhook_call"}`,
		"gravité":          `{"type":"notify","notify_severity":"fatal"}`,
	} {
		if rec := ruleCall(h, http.MethodPost, "/api/v1/rules-engine/rules", ruleJSON(action)); rec.Code != http.StatusBadRequest {
			t.Errorf("création, %s : %d (attendu 400)", name, rec.Code)
		}
	}
	rec := ruleCall(h, http.MethodPost, "/api/v1/rules-engine/rules", ruleJSON(`{"type":"ban_ip","ban_duration":"1h"}`))
	if rec.Code != http.StatusCreated {
		t.Fatalf("règle valide : %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if rec := ruleCall(h, http.MethodPut, "/api/v1/rules-engine/rules/"+out.ID, ruleJSON(`{"type":"ban_ip","ban_duration":"demain"}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("modification invalide : %d (attendu 400)", rec.Code)
	}
}

func TestScheduler_ActionIsValidated(t *testing.T) {
	_, h := newRuleHandlers(t)
	body := func(action string) string { return `{"name":"t","cron_expr":"0 3 * * *","action":` + action + `}` }
	if rec := ruleCall(h, http.MethodPost, "/api/v1/scheduled-tasks", body(`{"type":"explode"}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("type inconnu : %d", rec.Code)
	}
	if rec := ruleCall(h, http.MethodPost, "/api/v1/scheduled-tasks", body(`{"type":"run_backup","backup_retention":7}`)); rec.Code != http.StatusCreated {
		t.Errorf("action valide : %d %s", rec.Code, rec.Body.String())
	}
}

func TestRuleActionTypes_FromRegistry(t *testing.T) {
	h, _ := newRuleHandlers(t)
	rec := ruleCall(h, http.MethodGet, "/api/v1/rules-engine/action-types", "")
	var got []struct {
		Type   string   `json:"type"`
		Params []string `json:"params"`
		Edge   bool     `json:"edge"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 7 {
		t.Fatalf("types = %d, %v", len(got), err)
	}
	if got[1].Type != "ban_ip" || strings.Join(got[1].Params, ",") != "ban_reason,ban_duration" || !got[1].Edge {
		t.Errorf("ban_ip = %+v", got[1])
	}
}
