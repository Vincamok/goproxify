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

func TestDiscoverySources_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	DiscoverySourcesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/discovery-sources", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 7 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
	var order []string
	for _, m := range got {
		order = append(order, m.Type)
	}
	if strings.Join(order, " ") != "docker portainer kubernetes consul nomad etcd ecs" {
		t.Errorf("ordre : %v", order)
	}
	rec = httptest.NewRecorder()
	DiscoverySourcesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/discovery-sources", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST : %d", rec.Code)
	}
}
