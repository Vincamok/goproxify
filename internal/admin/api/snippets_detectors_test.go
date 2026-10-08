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
	"github.com/vincamok/goproxify/internal/modules"
)

func newSnippetsHandler(t *testing.T) *SnippetsHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "snip.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &SnippetsHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func snCall(h *SnippetsHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func createSnippet(t *testing.T, h *SnippetsHandler, body string) string {
	t.Helper()
	rec := snCall(h, http.MethodPost, "/api/v1/snippets", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestSnippets_DetectorConfigIsValidated(t *testing.T) {
	h := newSnippetsHandler(t)
	for name, body := range map[string]string{
		"mode ip_filter inconnu": `{"name":"a","type":"ip_filter","config":{"mode":"block","cidrs":["10.0.0.0/8"]}}`,
		"CIDR invalide":          `{"name":"b","type":"ip_filter","config":{"mode":"deny","cidrs":["10.0.0.0/40"]}}`,
		"pays invalide":          `{"name":"c","type":"geo_ip","config":{"mode":"deny","countries":["FRANCE"]}}`,
		"regex WAF invalide":     `{"name":"d","type":"waf","config":{"enabled":true,"custom_rules":[{"pattern":"("}]}}`,
		"clé inconnue":           `{"name":"e","type":"bot","config":{"enabled":true,"modee":"block"}}`,
	} {
		if rec := snCall(h, http.MethodPost, "/api/v1/snippets", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d (attendu 400)", name, rec.Code)
		}
	}
	createSnippet(t, h, `{"name":"ok1","type":"ip_filter","config":{"mode":"allow","cidrs":["10.0.0.0/8"]}}`)
	createSnippet(t, h, `{"name":"ok2","type":"geo_ip","config":{"mode":"deny","blocked_countries":["CN"]}}`)
	createSnippet(t, h, `{"name":"ok3","type":"rate_limit","config":{"anything":1}}`) // types libres inchangés
}

// Le secret du défi bot et la clé du captcha n'étaient pas masqués à la lecture.
func TestSnippets_BotSecretsMaskedAndKept(t *testing.T) {
	h := newSnippetsHandler(t)
	id := createSnippet(t, h, `{"name":"bot","type":"bot","config":{"enabled":true,"mode":"challenge","challenge_secret":"CH-SECRET","challenge_provider":"turnstile","challenge_site_key":"site","challenge_provider_secret":"CAPTCHA-SECRET"}}`)
	for _, path := range []string{"/api/v1/snippets", "/api/v1/snippets/" + id} {
		body := snCall(h, http.MethodGet, path, "").Body.String()
		if strings.Contains(body, "CH-SECRET") || strings.Contains(body, "CAPTCHA-SECRET") || !strings.Contains(body, "site") || !strings.Contains(body, modules.Masque) {
			t.Errorf("%s : %s", path, body)
		}
	}
	// Le formulaire renvoie ce qu'il a lu : secrets masqués, conservés.
	put := `{"name":"bot","type":"bot","config":{"enabled":true,"mode":"challenge","challenge_secret":"` + modules.Masque + `","challenge_provider":"turnstile","challenge_site_key":"site2","challenge_provider_secret":"` + modules.Masque + `"}}`
	if rec := snCall(h, http.MethodPut, "/api/v1/snippets/"+id, put); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body.String())
	}
	var raw string
	_ = h.DB.QueryRow(`SELECT config FROM snippets WHERE id=?`, id).Scan(&raw)
	if !strings.Contains(raw, "CH-SECRET") || !strings.Contains(raw, "CAPTCHA-SECRET") || !strings.Contains(raw, "site2") || strings.Contains(raw, modules.Masque) {
		t.Fatalf("config = %s", raw)
	}
}

func TestSnippets_UpdateValidatesAndHandlesMissing(t *testing.T) {
	h := newSnippetsHandler(t)
	id := createSnippet(t, h, `{"name":"ipf","type":"ip_filter","config":{"mode":"allow","cidrs":["10.0.0.0/8"]}}`)
	if rec := snCall(h, http.MethodPut, "/api/v1/snippets/"+id, `{"name":"ipf","type":"ip_filter","config":{"mode":"alow","cidrs":["10.0.0.0/8"]}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("mode invalide : %d", rec.Code)
	}
	if rec := snCall(h, http.MethodPut, "/api/v1/snippets/nope", `{"name":"x","type":"ip_filter","config":{"mode":"allow","cidrs":["10.0.0.0/8"]}}`); rec.Code != http.StatusNotFound {
		t.Errorf("inconnu : %d", rec.Code)
	}
	if rec := snCall(h, http.MethodPut, "/api/v1/snippets/"+id, `{"name":"ipf","type":"nimporte","config":{}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("type inconnu : %d", rec.Code)
	}
	var raw string
	_ = h.DB.QueryRow(`SELECT config FROM snippets WHERE id=?`, id).Scan(&raw)
	if !strings.Contains(raw, `"allow"`) {
		t.Errorf("config modifiée malgré le refus : %s", raw)
	}
}

func TestDetectorTypes_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	DetectorTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/detector-types", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 4 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
}
