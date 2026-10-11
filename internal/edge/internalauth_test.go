// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	edgetokens "github.com/vincamok/goproxify/internal/edge/tokens"
)

func TestInternalAPI_AgentTokenIsConfinedToAgentRoutes(t *testing.T) {
	ts, err := edgetokens.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	agentTok, _, err := ts.Create("node-a", edgetokens.RoleAgent, 0)
	if err != nil {
		t.Fatal(err)
	}
	adminTok, _, err := ts.Create("admin", edgetokens.RoleAdmin, 0)
	if err != nil {
		t.Fatal(err)
	}
	s := &Server{tokenStore: ts}
	h := s.authMiddleware(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) }))

	cases := []struct {
		method, path, token string
		want                int
	}{
		{"POST", "/internal/v1/agent/heartbeat", agentTok, 204},
		{"POST", "/internal/v1/agent/containers", agentTok, 204},
		{"DELETE", "/internal/v1/agent/containers", agentTok, 204},
		{"POST", "/internal/v1/agent/events", agentTok, 204},
		{"POST", "/internal/v1/agent/logs", agentTok, 204},
		{"DELETE", "/internal/v1/routes/k8s:default%2Fdemo", agentTok, 204},
		{"DELETE", "/internal/v1/routes/docker-host:app.example.fr", agentTok, 204},

		{"DELETE", "/internal/v1/routes/0b5f-config-route", agentTok, 403},
		{"DELETE", "/internal/v1/routes/deleg-x", agentTok, 403},
		{"POST", "/internal/v1/routes", agentTok, 403},
		{"POST", "/internal/v1/certs", agentTok, 403},
		{"GET", "/internal/v1/backup/export", agentTok, 403},
		{"POST", "/internal/v1/backup/restore", agentTok, 403},
		{"POST", "/internal/v1/agent/other-node/command", agentTok, 403},
		{"POST", "/internal/v1/agent/other-node/rescan", agentTok, 403},
		{"GET", "/internal/v1/agent/containers", agentTok, 403},
		{"GET", "/metrics", agentTok, 403},

		{"POST", "/internal/v1/certs", adminTok, 204},
		{"GET", "/internal/v1/backup/export", adminTok, 204},
		{"POST", "/internal/v1/agent/other-node/command", adminTok, 204},
		{"POST", "/internal/v1/certs", "gpx_admin_inconnu", 401},
		{"POST", "/internal/v1/certs", "", 401},
	}
	for _, c := range cases {
		req := httptest.NewRequest(c.method, c.path, nil)
		if c.token != "" {
			req.Header.Set("Authorization", "Bearer "+c.token)
		}
		rr := httptest.NewRecorder()
		h.ServeHTTP(rr, req)
		if rr.Code != c.want {
			t.Errorf("%s %s : %d, attendu %d", c.method, c.path, rr.Code, c.want)
		}
	}
}

func TestAgentIdentityBinding(t *testing.T) {
	ts, err := edgetokens.Open(filepath.Join(t.TempDir(), "tokens.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer ts.Close()
	tokA, _, _ := ts.Create("node-a", edgetokens.RoleAgent, 0)
	tokAdmin, _, _ := ts.Create("admin", edgetokens.RoleAdmin, 0)
	s := &Server{tokenStore: ts}

	call := func(token, claimed string) bool {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/agent/heartbeat", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		return s.agentMayActAs(httptest.NewRecorder(), req, claimed)
	}

	t.Setenv("GPX_AGENT_BIND_IDENTITY", "")
	if !call(tokA, "node-b") {
		t.Fatal("sans l'option, comportement inchangé")
	}

	t.Setenv("GPX_AGENT_BIND_IDENTITY", "true")
	if !call(tokA, "node-a") {
		t.Fatal("un Agent doit pouvoir agir en son nom")
	}
	if call(tokA, "node-b") {
		t.Fatal("un Agent ne doit pas agir au nom d'un autre")
	}
	if call(tokA, "") {
		t.Fatal("un nom absent ne doit pas passer")
	}
	if !call(tokAdmin, "node-b") {
		t.Fatal("un jeton d'administration (relais entre passerelles) n'est pas lié à un Agent")
	}
}
