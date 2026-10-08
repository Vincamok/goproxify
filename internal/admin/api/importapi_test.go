// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestImportConfigFormats(t *testing.T) {
	h := &ImportHandler{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/import/config-formats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range got {
		ids = append(ids, m.Type)
		if m.Label == "" || m.String("hint") == "" {
			t.Errorf("%s : libellé ou indication manquant", m.Type)
		}
	}
	want := "nginx,traefik-yaml,traefik-toml,caddy,haproxy,goproxify,json"
	if strings.Join(ids, ",") != want {
		t.Fatalf("formats = %v, attendu %s", ids, want)
	}
	if !strings.Contains(rec.Body.String(), `"fields":[]`) {
		t.Error("fields doit être [] (et non null) pour un format sans champ")
	}
}

func TestImportConfigFormats_RejectsOtherMethods(t *testing.T) {
	rec := httptest.NewRecorder()
	(&ImportHandler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/import/config-formats", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST : %d", rec.Code)
	}
}
