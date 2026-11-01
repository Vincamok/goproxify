// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"database/sql"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac/rbactest"
)

// grantViaTeam donne un accès à un compte comme le modèle le prévoit : par une équipe dont il est membre.
// Chaque appel crée sa propre équipe (nom unique), donc deux appels sur le même compte s'additionnent.
func grantViaTeam(t *testing.T, db *sql.DB, userID, scopeType, value, mode string) string {
	t.Helper()
	return rbactest.GrantViaTeam(t, db, userID, scopeType, value, mode)
}
