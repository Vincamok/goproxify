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
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 9 {
		t.Fatalf("types = %d, %v", len(got), err)
	}
	if got[1].Type != "ban_ip" || strings.Join(got[1].Params, ",") != "ban_reason,ban_duration" || !got[1].Edge {
		t.Errorf("ban_ip = %+v", got[1])
	}
}

func TestRules_ActionSecretsAreMaskedAndKept(t *testing.T) {
	h, _ := newRuleHandlers(t)
	const base = "/api/v1/rules-engine/rules"
	action := `{"type":"pagerduty","params":{"routing_key":"PD-SECRET","severity":"critical"}}`
	rec := ruleCall(h, http.MethodPost, base, ruleJSON(action))
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	if rec := ruleCall(h, http.MethodPost, base, ruleJSON(`{"type":"pagerduty","params":{"routing_key":"••••••••"}}`)); rec.Code != http.StatusBadRequest {
		t.Errorf("secret masqué accepté à la création : %d", rec.Code)
	}

	list := ruleCall(h, http.MethodGet, base, "")
	if strings.Contains(list.Body.String(), "PD-SECRET") || !strings.Contains(list.Body.String(), "critical") {
		t.Fatalf("liste = %s", list.Body.String())
	}

	if rec := ruleCall(h, http.MethodPut, base+"/"+created.ID, ruleJSON(`{"type":"pagerduty","params":{"routing_key":"••••••••","severity":"info"}}`)); rec.Code != http.StatusNoContent {
		t.Fatalf("modification : %d %s", rec.Code, rec.Body.String())
	}
	var stored string
	if err := h.DB.QueryRow(`SELECT action_json FROM rules_engine_rules WHERE id=?`, created.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(stored, "PD-SECRET") || !strings.Contains(stored, "info") {
		t.Errorf("secret perdu ou gravité non mise à jour : %s", stored)
	}

	export := ruleCall(h, http.MethodGet, base[:len(base)-len("/rules")]+"/export", "")
	if export.Code != http.StatusOK || strings.Contains(export.Body.String(), "PD-SECRET") {
		t.Errorf("export = %d %s", export.Code, export.Body.String())
	}
	imp := ruleCall(h, http.MethodPost, base[:len(base)-len("/rules")]+"/import", export.Body.String())
	if imp.Code != http.StatusOK {
		t.Fatalf("import : %d %s", imp.Code, imp.Body.String())
	}
	_ = h.DB.QueryRow(`SELECT action_json FROM rules_engine_rules WHERE id=?`, created.ID).Scan(&stored)
	if !strings.Contains(stored, "PD-SECRET") {
		t.Errorf("l'import d'un export masqué a écrasé le secret : %s", stored)
	}
}

func TestAutomationExport_MasksChannelSecrets(t *testing.T) {
	h, _ := newRuleHandlers(t)
	if _, err := h.DB.Exec(`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES ('c1','hook','webhook','{"url":"https://x.example.com","secret":"HMAC-SECRET"}',1)`); err != nil {
		t.Fatal(err)
	}
	export := ruleCall(h, http.MethodGet, "/api/v1/rules-engine/export", "")
	if strings.Contains(export.Body.String(), "HMAC-SECRET") || !strings.Contains(export.Body.String(), "https://x.example.com") {
		t.Fatalf("export = %s", export.Body.String())
	}
	if rec := ruleCall(h, http.MethodPost, "/api/v1/rules-engine/import", export.Body.String()); rec.Code != http.StatusOK {
		t.Fatalf("import : %d %s", rec.Code, rec.Body.String())
	}
	var cfg string
	_ = h.DB.QueryRow(`SELECT config FROM alert_channels WHERE name='hook'`).Scan(&cfg)
	if !strings.Contains(cfg, "HMAC-SECRET") {
		t.Errorf("secret du canal écrasé par l'import : %s", cfg)
	}
}
