// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/automation"
)

func newAutomationHandler(t *testing.T) *AutomationHandler {
	t.Helper()
	db := openSQLDatesDB(t)
	return &AutomationHandler{Svc: automation.New(db, slog.Default(), automation.Deps{}, automation.Options{})}
}

func pagerFlow(key, severity string) map[string]any {
	return map[string]any{
		"name": "incident", "enabled": true,
		"trigger": map[string]any{"kind": "manual"},
		"steps": []any{map[string]any{"id": "pd", "type": "action",
			"action": map[string]any{"type": "pagerduty", "config": map[string]any{"routing_key": key, "severity": severity}}}},
	}
}

func TestAutomationAPI_SecretsMaskedAndKept(t *testing.T) {
	h := newAutomationHandler(t)
	const base = "/api/v1/automation/flows"
	rec := serve(t, h, http.MethodPost, base, pagerFlow("PD-SECRET", "critical"))
	if rec.Code != http.StatusOK {
		t.Fatalf("création : %d %s", rec.Code, rec.Body)
	}
	var created automation.Flow
	_ = json.Unmarshal(rec.Body.Bytes(), &created)

	other := pagerFlow("••••••••", "critical")
	other["name"] = "autre"
	if rec := serve(t, h, http.MethodPost, base, other); rec.Code != http.StatusBadRequest {
		t.Errorf("secret masqué accepté à la création : %d", rec.Code)
	}
	list := serve(t, h, http.MethodGet, base+"?trigger=manual", nil)
	if strings.Contains(list.Body.String(), "PD-SECRET") || !strings.Contains(list.Body.String(), "critical") {
		t.Fatalf("liste = %s", list.Body)
	}
	if rec := serve(t, h, http.MethodPut, base+"/"+created.ID, pagerFlow("••••••••", "info")); rec.Code != http.StatusOK {
		t.Fatalf("modification : %d %s", rec.Code, rec.Body)
	}
	var stored string
	stored = storedDefinition(t, h, created.ID)
	if !strings.Contains(stored, "PD-SECRET") || !strings.Contains(stored, "info") {
		t.Errorf("secret perdu ou gravité non mise à jour : %s", stored)
	}

	if _, err := h.Svc.CreateSilence(t.Context(), automation.Silence{Name: "x", StartsAt: created.CreatedAt, EndsAt: created.CreatedAt.AddDate(0, 0, 1)}); err != nil {
		t.Fatal(err)
	}
	h.Svc.Delete(t.Context(), "inexistant") //nolint:errcheck
	export := serve(t, h, http.MethodGet, "/api/v1/automation/export", nil)
	if export.Code != http.StatusOK || strings.Contains(export.Body.String(), "PD-SECRET") {
		t.Fatalf("export = %d %s", export.Code, export.Body)
	}
	if imp := serve(t, h, http.MethodPost, "/api/v1/automation/import", export.Body.String()); imp.Code != http.StatusOK {
		t.Fatalf("import : %d %s", imp.Code, imp.Body)
	}
	if stored = storedDefinition(t, h, created.ID); !strings.Contains(stored, "PD-SECRET") {
		t.Errorf("l'import d'un export masqué a écrasé le secret : %s", stored)
	}
}

func storedDefinition(t *testing.T, h *AutomationHandler, id string) string {
	t.Helper()
	data, err := h.Svc.Export(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	_ = data
	var def string
	// La base garde la valeur en clair ; seule la sortie est masquée.
	row := h.Svc.DB().QueryRow(`SELECT definition_json FROM flows WHERE id=?`, id)
	if err := row.Scan(&def); err != nil {
		t.Fatal(err)
	}
	return def
}

func TestAutomationAPI_ExportMasksChannelSecrets(t *testing.T) {
	h := newAutomationHandler(t)
	if _, err := h.Svc.DB().Exec(`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES ('c1','hook','webhook','{"url":"https://x.example.com","secret":"HMAC-SECRET"}',1)`); err != nil {
		t.Fatal(err)
	}
	export := serve(t, h, http.MethodGet, "/api/v1/automation/export", nil)
	if strings.Contains(export.Body.String(), "HMAC-SECRET") || !strings.Contains(export.Body.String(), "https://x.example.com") {
		t.Fatalf("export = %s", export.Body)
	}
	if rec := serve(t, h, http.MethodPost, "/api/v1/automation/import", export.Body.String()); rec.Code != http.StatusOK {
		t.Fatalf("import : %d %s", rec.Code, rec.Body)
	}
	var cfg string
	_ = h.Svc.DB().QueryRow(`SELECT config FROM alert_channels WHERE name='hook'`).Scan(&cfg)
	if !strings.Contains(cfg, "HMAC-SECRET") {
		t.Errorf("secret du canal écrasé par l'import : %s", cfg)
	}
}

func TestAutomationAPI_StatusCodes(t *testing.T) {
	h := newAutomationHandler(t)
	if rec := serve(t, h, http.MethodGet, "/api/v1/automation/flows/inconnu", nil); rec.Code != http.StatusNotFound {
		t.Errorf("flux inconnu : %d", rec.Code)
	}
	rec := serve(t, h, http.MethodPost, "/api/v1/automation/templates/cve-high-notify/install", map[string]any{"enabled": true})
	if rec.Code != http.StatusOK {
		t.Fatalf("installation : %d %s", rec.Code, rec.Body)
	}
	var f automation.Flow
	_ = json.Unmarshal(rec.Body.Bytes(), &f)
	if rec := serve(t, h, http.MethodPut, "/api/v1/automation/flows/"+f.ID, map[string]any{
		"name": f.Name, "enabled": true, "origin": map[string]any{"kind": "template", "params": map[string]any{"cvss": 8}}}); rec.Code != http.StatusOK {
		t.Fatalf("paramètres : %d %s", rec.Code, rec.Body)
	}
	if rec := serve(t, h, http.MethodPut, "/api/v1/automation/flows/"+f.ID, pagerFlow("k", "info")); rec.Code != http.StatusConflict {
		t.Errorf("définition d'un flux de modèle modifiée : %d", rec.Code)
	}
	if rec := serve(t, h, http.MethodGet, "/api/v1/automation/catalog", nil); rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "metric_threshold") {
		t.Errorf("catalogue : %d", rec.Code)
	}
	if rec := serve(t, h, http.MethodGet, "/api/v1/automation/options/boom", nil); rec.Code != http.StatusBadRequest {
		t.Errorf("source inconnue : %d", rec.Code)
	}
	if rec := serve(t, h, http.MethodPost, "/api/v1/automation/simulate", map[string]any{"flow": pagerFlow("k", "info")}); rec.Code != http.StatusOK {
		t.Errorf("simulation : %d %s", rec.Code, rec.Body)
	}
}
