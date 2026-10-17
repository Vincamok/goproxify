// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func announceContainer(t *testing.T, s *Server, cid, backend string) {
	t.Helper()
	b, _ := json.Marshal(map[string]any{
		"id": "docker:" + cid[:12] + ":app.example.fr", "host": "app.example.fr",
		"backends": []string{backend}, "container_id": cid, "agent_name": "ag",
	})
	rr := httptest.NewRecorder()
	s.handleAgentContainerStart(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewReader(b)))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("status = %d", rr.Code)
	}
}

func listAgentContainersJSON(t *testing.T, s *Server) []map[string]any {
	t.Helper()
	rr := httptest.NewRecorder()
	s.handleListAgentContainers(rr, httptest.NewRequest(http.MethodGet, "/internal/v1/agent/containers", nil))
	var out []map[string]any
	if err := json.NewDecoder(rr.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	return out
}

func TestConfiguredProxyKeepsHostAgainstContainerLabels(t *testing.T) {
	s := testEdgeServer()
	s.table.Upsert(&router.Route{ID: "proxy-1", Host: "app.example.fr", Backends: []router.Backend{{URL: "http://managed:80"}}})

	announceContainer(t, s, "aaaaaaaaaaaa1111", "http://10.0.0.1:80")
	announceContainer(t, s, "bbbbbbbbbbbb2222", "http://10.0.0.2:80")

	if rt, _ := s.table.ByHost("app.example.fr"); rt == nil || rt.ID != "proxy-1" {
		t.Fatalf("le proxy configuré doit garder l'hôte, obtenu %+v", rt)
	}
	got := listAgentContainersJSON(t, s)
	if len(got) != 1 || got[0]["shadowed_by"] != "proxy-1" {
		t.Fatalf("la route des labels doit se dire remplacée par proxy-1, obtenu %v", got)
	}
	if b, _ := got[0]["backends"].([]any); len(b) != 2 {
		t.Fatalf("le pool des conteneurs reste complet malgré le proxy, obtenu %v", got[0]["backends"])
	}
}

func TestListAgentContainersExportsProxyConfigWithoutContainerBinding(t *testing.T) {
	s := testEdgeServer()
	announceContainer(t, s, "aaaaaaaaaaaa1111", "http://10.0.0.1:80")
	got := listAgentContainersJSON(t, s)
	raw, _ := json.Marshal(got[0]["proxy_config"])
	var cfg router.Route
	if err := json.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if cfg.Host != "app.example.fr" || len(cfg.Backends) != 1 || cfg.Backends[0].URL != "http://10.0.0.1:80" {
		t.Fatalf("config incomplète : %s", raw)
	}
	if cfg.ID != "" || cfg.AgentName != "" || cfg.Backends[0].ContainerID != "" {
		t.Fatalf("la config ne doit pas porter de lien au conteneur : %s", raw)
	}
}

func TestDisabledProxyHandsHostBackToContainerLabels(t *testing.T) {
	s := testEdgeServer()
	s.table.Upsert(&router.Route{ID: "proxy-1", Host: "app.example.fr", Backends: []router.Backend{{URL: "http://managed:80"}}})
	announceContainer(t, s, "aaaaaaaaaaaa1111", "http://10.0.0.1:80")

	s.table.Delete("proxy-1")
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok || rt.ID != "docker-host:app.example.fr" {
		t.Fatalf("la route des labels reprend l'hôte, obtenu %+v", rt)
	}
	if got := listAgentContainersJSON(t, s); got[0]["shadowed_by"] != nil {
		t.Fatalf("plus remplacée, obtenu %v", got[0]["shadowed_by"])
	}
}
