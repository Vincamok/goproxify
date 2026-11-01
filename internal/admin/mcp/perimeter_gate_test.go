// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"strings"
	"testing"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/admin/rbac/rbactest"
)

// Les outils qui lisent logs, certificats, alertes ou métriques sans filtrer par hôte sont refusés à un accès à
// périmètre, ouverts à un accès sans critère et à un administrateur.
func TestPerimeterBoundToolsNeedAnUnrestrictedAccess(t *testing.T) {
	h := setupMCPDB(t)
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('scoped','s@t','x','user'), ('open','o@t','x','user'), ('nobody','n@t','x','user'), ('boss','b@t','x','admin')`,
		`INSERT INTO teams (id, name) VALUES ('ts','ts'), ('to','to')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('ts','scoped'), ('to','open')`,
	} {
		if _, err := h.DB.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	levels := map[string]string{"logs": "read", "certs": "read", "alerts": "read", "dashboard": "read"}
	rbactest.AddAccess(t, h.DB, "ts", rbac.TeamAccess{Name: "scoped", Levels: levels, Perimeter: rbac.Perimeter{Domain: "*.corp.io"}})
	rbactest.AddAccess(t, h.DB, "to", rbac.TeamAccess{Name: "open", Levels: levels})

	for _, c := range []struct {
		user, tool string
		deny       string // sous-chaîne attendue du refus, "" = autorisé
	}{
		{"scoped", "list_logs", "sans périmètre"},
		{"scoped", "list_certs", "sans périmètre"},
		{"scoped", "list_alert_events", "sans périmètre"},
		{"scoped", "get_metrics", "sans périmètre"},
		{"open", "list_logs", ""},
		{"open", "list_certs", ""},
		{"boss", "list_logs", ""},
		{"nobody", "list_logs", "insuffisant"},
		// Un outil qui ne figure pas dans la liste n'est pas concerné par cette garde.
		{"scoped", "list_snippets", ""},
	} {
		ctx := adminauth.WithUserID(context.Background(), c.user)
		got := h.denyPerimeterBound(ctx, c.tool)
		if (c.deny == "") != (got == "") || (c.deny != "" && !strings.Contains(got, c.deny)) {
			t.Errorf("%s / %s : %q, attendu %q", c.user, c.tool, got, c.deny)
		}
	}
}

// Tout outil de la liste existe et a une permission du catalogue : sinon la garde ne filtrerait rien.
func TestPerimeterBoundToolsAreRealTools(t *testing.T) {
	for _, tool := range perimeterBoundTools {
		if !listedTool(tool) {
			t.Errorf("%s : n'est pas un outil MCP", tool)
		}
		if rbac.ToolPermission(tool) == "" {
			t.Errorf("%s : aucune permission déclarée", tool)
		}
	}
}
