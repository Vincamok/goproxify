// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

func toolNames() []string {
	names := make([]string, 0, len(tools))
	for _, t := range tools {
		names = append(names, t["name"].(string))
	}
	return names
}

func TestEveryToolHasScope(t *testing.T) {
	for _, name := range toolNames() {
		scope := rbac.ToolRequiredScope(name)
		if scope == "" {
			t.Errorf("%s : aucun scope déclaré dans rbac.ToolRequiredScope", name)
			continue
		}
		if !rbac.IsKnownScope(scope) {
			t.Errorf("%s : scope %q absent du catalogue", name, scope)
		}
	}
}

// Le catalogue scope → outils de /mcp-access (dérivé de rbac.mcpTools) doit lister
// chaque outil une fois, et aucun outil inexistant.
func TestScopeCatalogueListsEveryTool(t *testing.T) {
	var catalogue []string
	for _, scope := range rbac.AllPATScopes {
		catalogue = append(catalogue, rbac.ToolsForScope(scope)...)
	}
	slices.Sort(catalogue)
	if dup := slices.Compact(slices.Clone(catalogue)); len(dup) != len(catalogue) {
		t.Fatalf("outil en double dans rbac.mcpTools")
	}
	want := toolNames()
	slices.Sort(want)
	for _, name := range want {
		if _, found := slices.BinarySearch(catalogue, name); !found {
			t.Errorf("%s : absent de rbac.mcpTools", name)
		}
	}
	for _, name := range catalogue {
		if _, found := slices.BinarySearch(want, name); !found {
			t.Errorf("%s : dans rbac.mcpTools mais pas exposé par le serveur MCP", name)
		}
	}
}

func TestEveryResourceMapsToTool(t *testing.T) {
	h := &Handler{}
	resp := h.handleResourcesList(rpcRequest{})
	list := resp.Result.(map[string]any)["resources"].([]map[string]any)
	if len(list) != len(resourceTools) {
		t.Fatalf("%d ressources listées, %d dans resourceTools", len(list), len(resourceTools))
	}
	for _, res := range list {
		uri := res["uri"].(string)
		tool, ok := resourceTools[uri]
		if !ok {
			t.Errorf("%s : absente de resourceTools", uri)
			continue
		}
		if !listedTool(tool) {
			t.Errorf("%s : outil %q inconnu", uri, tool)
		}
	}
}

// mcpClient appelle /mcp comme en production (RequirePAT) avec un PAT portant scopes.
func mcpClient(t *testing.T, h *Handler, userID, role string, scopes ...string) func(method string, params any) rpcResponse {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?,?,?,?)`,
		userID, userID+"@t.local", "x", role); err != nil {
		t.Fatal(err)
	}
	plain := adminauth.GeneratePAT()
	if _, err := h.DB.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES (?,?,?,?,?)`,
		"pat-"+userID, userID, "t", adminauth.HashPAT(plain), adminauth.PATPreview(plain)); err != nil {
		t.Fatal(err)
	}
	for _, s := range scopes {
		if _, err := h.DB.Exec(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES (?,?)`, "pat-"+userID, s); err != nil {
			t.Fatal(err)
		}
	}
	srv := adminauth.RequirePAT(h.DB)(h)
	return func(method string, params any) rpcResponse {
		p, _ := json.Marshal(params)
		body, _ := json.Marshal(map[string]any{"jsonrpc": "2.0", "id": 1, "method": method, "params": json.RawMessage(p)})
		r := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(body))
		r.RemoteAddr = "127.0.0.1:40000"
		r.Header.Set("Authorization", "Bearer "+plain)
		w := httptest.NewRecorder()
		srv.ServeHTTP(w, r)
		var resp rpcResponse
		if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
			t.Fatalf("%s : réponse illisible %q", method, w.Body.String())
		}
		return resp
	}
}

// callText retourne le texte d'un tools/call et s'il s'agit d'une erreur.
func callText(t *testing.T, resp rpcResponse) (string, bool) {
	t.Helper()
	if resp.Error != nil {
		t.Fatalf("erreur JSON-RPC inattendue : %s", resp.Error.Message)
	}
	b, _ := json.Marshal(resp.Result)
	var res struct {
		Content []struct{ Text string } `json:"content"`
		IsError bool                    `json:"isError"`
	}
	_ = json.Unmarshal(b, &res)
	if len(res.Content) == 0 {
		t.Fatalf("résultat sans contenu : %s", b)
	}
	return res.Content[0].Text, res.IsError
}

func TestToolsCallAuthorization(t *testing.T) {
	h := setupMCPDB(t)
	// Compte user avec tous les scopes qu'il peut détenir (lectures communes).
	asUser := mcpClient(t, h, "u", "user",
		rbac.ScopeProxiesRead, rbac.ScopeNodesRead, rbac.ScopeAlertsRead, rbac.ScopeMetricsRead,
		rbac.ScopeBackupsRead, rbac.ScopeSnippetsRead, rbac.ScopeDomainsRead, rbac.ScopeCertsRead,
		rbac.ScopeLogsRead, rbac.ScopeAuditRead)
	asAdmin := mcpClient(t, h, "a", "admin", rbac.ScopeAuditRead)

	call := func(client func(string, any) rpcResponse, tool string) (string, bool) {
		return callText(t, client("tools/call", map[string]any{"name": tool, "arguments": map[string]any{}}))
	}

	for _, c := range []struct {
		name   string
		client func(string, any) rpcResponse
		tool   string
		denied string
	}{
		{"user lit ses alertes", asUser, "list_alert_channels", ""},
		{"user lit l'audit (route non admin)", asUser, "get_audit_log", ""},
		{"user sans alerts:write", asUser, "create_alert_channel", "scope insuffisant: " + rbac.ScopeAlertsWrite},
		{"user sans certs:write", asUser, "obtain_cert", "scope insuffisant: " + rbac.ScopeCertsWrite},
		{"user sans domains:write", asUser, "rotate_cert", "scope insuffisant: " + rbac.ScopeDomainsWrite},
		{"user sans security:write", asUser, "run_playbook_now", "scope insuffisant: " + rbac.ScopeSecurityWrite},
		{"user, route REST adminOnly", asUser, "list_rules", "accès réservé aux administrateurs"},
		{"user, CA interne adminOnly", asUser, "list_internal_cas", "accès réservé aux administrateurs"},
		{"user, bans adminOnly", asUser, "list_security_bans", "accès réservé aux administrateurs"},
		{"user, fournisseurs d'auth adminOnly", asUser, "list_auth_providers", "accès réservé aux administrateurs"},
		{"admin avec audit:read", asAdmin, "list_auth_providers", ""},
		{"admin sans security:write", asAdmin, "delete_auth_provider", "scope insuffisant: " + rbac.ScopeSecurityWrite},
		{"admin sans alerts:read", asAdmin, "list_alert_rules", "scope insuffisant: " + rbac.ScopeAlertsRead},
	} {
		text, isErr := call(c.client, c.tool)
		switch {
		case c.denied == "" && strings.HasPrefix(text, "Erreur: ") &&
			(strings.Contains(text, "scope") || strings.Contains(text, "administrateurs")):
			t.Errorf("%s : %s refusé à tort (%s)", c.name, c.tool, text)
		case c.denied != "" && (!isErr || text != "Erreur: "+c.denied):
			t.Errorf("%s : %s → %q, attendu %q", c.name, c.tool, text, "Erreur: "+c.denied)
		}
	}

	if resp := asAdmin("tools/call", map[string]any{"name": "no_such_tool"}); resp.Error == nil || resp.Error.Code != -32601 {
		t.Fatalf("outil inconnu : %+v", resp)
	}
}

func TestToolWithoutScopeIsDenied(t *testing.T) {
	h := setupMCPDB(t)
	asAdmin := mcpClient(t, h, "a", "admin", rbac.AllPATScopes...)
	orig := tools
	t.Cleanup(func() { tools = orig })
	tools = append(slices.Clip(tools), map[string]any{"name": "zz_unscoped_tool"})

	text, isErr := callText(t, asAdmin("tools/call", map[string]any{"name": "zz_unscoped_tool"}))
	if !isErr || text != "Erreur: outil sans scope déclaré: zz_unscoped_tool" {
		t.Fatalf("outil sans scope : %q", text)
	}
}

func TestResourcesReadAuthorization(t *testing.T) {
	h := setupMCPDB(t)
	asUser := mcpClient(t, h, "u", "user", rbac.ScopeProxiesRead, rbac.ScopeAuditRead)

	if resp := asUser("resources/read", map[string]any{"uri": "goproxify://users"}); resp.Error == nil ||
		resp.Error.Message != "scope insuffisant: "+rbac.ScopeUsersRead {
		t.Fatalf("goproxify://users : %+v", resp)
	}
	if resp := asUser("resources/read", map[string]any{"uri": "goproxify://security/bans"}); resp.Error == nil ||
		resp.Error.Message != "accès réservé aux administrateurs" {
		t.Fatalf("goproxify://security/bans : %+v", resp)
	}
	if resp := asUser("resources/read", map[string]any{"uri": "goproxify://proxies"}); resp.Error != nil {
		t.Fatalf("goproxify://proxies : %s", resp.Error.Message)
	}
	if resp := asUser("resources/read", map[string]any{"uri": "goproxify://nope"}); resp.Error == nil || resp.Error.Code != -32002 {
		t.Fatalf("ressource inconnue : %+v", resp)
	}
}
