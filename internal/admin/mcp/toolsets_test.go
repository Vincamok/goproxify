// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

func listedNames(t *testing.T, resp rpcResponse) []string {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("tools/list : %s", resp.Error.Message)
	}
	b, _ := json.Marshal(resp.Result)
	var res struct {
		Tools []struct{ Name string } `json:"tools"`
	}
	_ = json.Unmarshal(b, &res)
	names := make([]string, 0, len(res.Tools))
	for _, tool := range res.Tools {
		names = append(names, tool.Name)
	}
	return names
}

func TestEveryToolHasToolset(t *testing.T) {
	used := map[string]bool{}
	for _, name := range toolNames() {
		set := toolsetOf(name)
		if !slices.Contains(toolsetNames, set) {
			t.Errorf("%s : groupe %q inconnu", name, set)
		}
		used[set] = true
	}
	for _, set := range toolsetNames {
		if !used[set] {
			t.Errorf("groupe %q vide", set)
		}
	}
}

func TestToolsListAdminAllScopes(t *testing.T) {
	h := setupMCPDB(t)
	asAdmin := mcpClient(t, h, "a", "admin", rbac.AllPATScopes...)
	if got := listedNames(t, asAdmin("tools/list", nil)); len(got) != len(tools) {
		t.Fatalf("%d outils listés, %d attendus", len(got), len(tools))
	}
}

func TestToolsListFiltersByScope(t *testing.T) {
	h := setupMCPDB(t)
	asUser := mcpClient(t, h, "u", "user", rbac.ScopeProxiesRead, rbac.ScopeAuditRead)
	got := listedNames(t, asUser("tools/list", nil))
	for _, name := range got {
		scope := rbac.ToolRequiredScope(name)
		if scope != rbac.ScopeProxiesRead && scope != rbac.ScopeAuditRead {
			t.Errorf("%s listé sans son scope %s", name, scope)
		}
		if rbac.ToolRequiresAdmin(name) {
			t.Errorf("%s (réservé admin) listé pour un user", name)
		}
	}
	for _, want := range []string{"list_proxies", "get_proxy", "get_audit_log"} {
		if !slices.Contains(got, want) {
			t.Errorf("%s absent", want)
		}
	}
}

func TestToolsListToolsets(t *testing.T) {
	h := setupMCPDB(t)
	asAdmin := mcpClientAt(t, h, "/mcp?toolsets=proxies,%20Alerts", "a", "admin", rbac.AllPATScopes...)
	got := listedNames(t, asAdmin("tools/list", nil))
	if len(got) == 0 {
		t.Fatal("aucun outil listé")
	}
	for _, name := range got {
		if set := toolsetOf(name); set != "proxies" && set != "alerts" {
			t.Errorf("%s (groupe %s) listé hors des groupes demandés", name, set)
		}
	}

	bad := mcpClientAt(t, h, "/mcp?toolsets=proxies,nope", "b", "admin", rbac.AllPATScopes...)
	resp := bad("tools/list", nil)
	if resp.Error == nil || resp.Error.Code != -32602 || !strings.Contains(resp.Error.Message, "toolset inconnu: nope") {
		t.Fatalf("groupe inconnu : %+v", resp)
	}
}

func TestSSEEndpointKeepsToolsets(t *testing.T) {
	h := setupMCPDB(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	r := httptest.NewRequest(http.MethodGet, "/mcp/sse?toolsets=proxies", nil).WithContext(ctx)
	r.RemoteAddr = "127.0.0.1:40000"
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	if want := "data: http://example.com/mcp?toolsets=proxies\n"; !strings.Contains(w.Body.String(), want) {
		t.Fatalf("endpoint SSE : %q", w.Body.String())
	}
}
