// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"database/sql"
	"testing"

	"github.com/google/uuid"
)

// grantViaTeam donne un accès à un compte comme le modèle le prévoit : par une équipe dont il est membre.
// Chaque appel crée sa propre équipe (nom unique), donc deux appels sur le même compte s'additionnent.
func grantViaTeam(t *testing.T, db *sql.DB, userID, scopeType, value, mode string) string {
	t.Helper()
	teamID := uuid.New().String()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO teams (id, name) VALUES (?, ?)`, []any{teamID, "equipe-" + teamID}},
		{`INSERT INTO team_members (team_id, user_id) VALUES (?, ?)`, []any{teamID, userID}},
		{`INSERT INTO team_scopes (id, team_id, scope_type, scope_value, access_mode) VALUES (?, ?, ?, ?, ?)`,
			[]any{uuid.New().String(), teamID, scopeType, value, mode}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	return teamID
}
