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

	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/modules"
)

func newProvidersHandler(t *testing.T) *ACMEProvidersHandler {
	t.Helper()
	return &ACMEProvidersHandler{
		Store: acme.NewProviderStore(filepath.Join(t.TempDir(), "providers.yaml")),
		Log:   slog.New(slog.NewTextHandler(io.Discard, nil)),
	}
}

func provCall(h *ACMEProvidersHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func createProvider(t *testing.T, h *ACMEProvidersHandler, body string) string {
	t.Helper()
	rec := provCall(h, http.MethodPost, "/api/v1/acme/providers", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out["id"]
}

func TestACMEProviders_CreateValidates(t *testing.T) {
	h := newProvidersHandler(t)
	for name, body := range map[string]string{
		"type inconnu":      `{"name":"x","type":"carrier-pigeon","params":{}}`,
		"champ requis":      `{"name":"x","type":"cloudflare","params":{}}`,
		"clé inconnue":      `{"name":"x","type":"gandi","params":{"api_key":"k","typo":"1"}}`,
		"hetzner sans zone": `{"name":"x","type":"hetzner","params":{"api_token":"t"}}`,
	} {
		if rec := provCall(h, http.MethodPost, "/api/v1/acme/providers", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d (attendu 400)", name, rec.Code)
		}
	}
	createProvider(t, h, `{"name":"cf","type":"cloudflare","params":{"api_token":"tok-secret"}}`)
}

// Les paramètres secrets ne sortent plus de GET /acme/providers (ni en liste, ni au détail).
func TestACMEProviders_ReadsMaskSecrets(t *testing.T) {
	h := newProvidersHandler(t)
	id := createProvider(t, h, `{"name":"ovh","type":"ovh","params":{"app_key":"AK-SECRET","app_secret":"AS-SECRET","consumer_key":"CK-SECRET","zone":"example.com"}}`)
	for _, path := range []string{"/api/v1/acme/providers", "/api/v1/acme/providers/" + id} {
		body := provCall(h, http.MethodGet, path, "").Body.String()
		for _, leaked := range []string{"AK-SECRET", "AS-SECRET", "CK-SECRET"} {
			if strings.Contains(body, leaked) {
				t.Errorf("%s expose %s", path, leaked)
			}
		}
		if !strings.Contains(body, "example.com") || !strings.Contains(body, modules.Masque) {
			t.Errorf("%s : zone absente ou secrets non masqués : %s", path, body)
		}
	}
	// Le fichier, lui, garde les vraies valeurs (c'est la source des émissions).
	e, _ := h.Store.Get(id)
	if e.Params["app_key"] != "AK-SECRET" {
		t.Fatalf("valeur stockée = %q", e.Params["app_key"])
	}
}

func TestACMEProviders_UpdateKeepsOmittedAndMaskedSecrets(t *testing.T) {
	h := newProvidersHandler(t)
	id := createProvider(t, h, `{"name":"cf","type":"cloudflare","params":{"api_token":"tok-secret","zone_id":"z1"}}`)

	for name, body := range map[string]string{
		"omis":   `{"name":"cf2","type":"cloudflare","params":{"zone_id":"z2"}}`,
		"masqué": `{"name":"cf2","type":"cloudflare","params":{"api_token":"` + modules.Masque + `","zone_id":"z2"}}`,
	} {
		if rec := provCall(h, http.MethodPut, "/api/v1/acme/providers/"+id, body); rec.Code != http.StatusNoContent {
			t.Fatalf("%s : %d %s", name, rec.Code, rec.Body.String())
		}
		e, _ := h.Store.Get(id)
		if e.Params["api_token"] != "tok-secret" || e.Params["zone_id"] != "z2" || e.Name != "cf2" {
			t.Fatalf("%s : entrée = %+v", name, e)
		}
	}
	if rec := provCall(h, http.MethodPut, "/api/v1/acme/providers/"+id, `{"name":"cf2","type":"cloudflare","params":{"api_token":"nouveau"}}`); rec.Code != http.StatusNoContent {
		t.Fatal(rec.Code)
	}
	if e, _ := h.Store.Get(id); e.Params["api_token"] != "nouveau" {
		t.Fatalf("nouveau secret non enregistré : %+v", e)
	}
}

func TestACMEProviders_TypeChangeDoesNotReuseOldSecrets(t *testing.T) {
	h := newProvidersHandler(t)
	id := createProvider(t, h, `{"name":"x","type":"gandi","params":{"api_key":"gandi-secret"}}`)
	// Passer à Cloudflare sans jeton : le secret Gandi ne doit pas servir, la validation refuse.
	if rec := provCall(h, http.MethodPut, "/api/v1/acme/providers/"+id, `{"name":"x","type":"cloudflare","params":{}}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestACMEProviders_UpdateUnknownIsNotFound(t *testing.T) {
	h := newProvidersHandler(t)
	if rec := provCall(h, http.MethodPut, "/api/v1/acme/providers/nope", `{"name":"x","type":"gandi","params":{"api_key":"k"}}`); rec.Code != http.StatusNotFound {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestACMEProviderTypes_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	ACMEProviderTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/acme/provider-types", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 5 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
	if got[0].Type != "ovh" {
		t.Errorf("ordre : %s", got[0].Type)
	}
	rec = httptest.NewRecorder()
	ACMEProviderTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/acme/provider-types", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST : %d", rec.Code)
	}
}
