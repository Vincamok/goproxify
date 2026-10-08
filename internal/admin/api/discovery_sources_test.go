// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestDiscoverySources_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	DiscoverySourcesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/discovery-sources", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 3 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
	if got[0].Type != "docker" || got[1].Type != "portainer" || got[2].Type != "kubernetes" {
		t.Errorf("ordre : %s %s %s", got[0].Type, got[1].Type, got[2].Type)
	}
	rec = httptest.NewRecorder()
	DiscoverySourcesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/discovery-sources", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST : %d", rec.Code)
	}
}
