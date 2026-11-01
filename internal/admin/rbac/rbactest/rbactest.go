// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package rbactest aide les tests à donner un accès à un compte par une équipe.
package rbactest

import (
	"context"
	"database/sql"
	"testing"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// Access construit l'accès que les anciens tests décrivaient par (type, valeur, mode) : un seul critère, et le niveau
// « Lecture » (mode read) ou « Exploitation » (mode write) des services qui en dépendent.
func Access(scopeType, value, mode string) rbac.TeamAccess {
	a := rbac.TeamAccess{Name: scopeType + ":" + value, Levels: map[string]string{"proxies": "read", "containers": "read", "surface": "read", "domains": "read"}}
	if mode == "write" {
		a.Levels = map[string]string{"proxies": "operate", "containers": "operate", "surface": "learn", "domains": "read"}
	}
	switch scopeType {
	case "domain":
		a.Perimeter.Domain = value
	case "proxy":
		a.Perimeter.Proxy = value
	case "server":
		a.Perimeter.Backend = value
	case "edge":
		a.Perimeter.Group.Name = value
	}
	return a
}

// AddAccess enregistre un accès pour une équipe qui existe déjà.
func AddAccess(t testing.TB, db *sql.DB, teamID string, a rbac.TeamAccess) string {
	t.Helper()
	a.ID, a.TeamID = uuid.New().String(), teamID
	if err := rbac.SaveTeamAccess(context.Background(), db, a); err != nil {
		t.Fatalf("SaveTeamAccess: %v", err)
	}
	return a.ID
}

// GrantViaTeam donne un accès à un compte comme le modèle le prévoit : par une équipe dont il est membre. Chaque appel
// crée sa propre équipe (nom unique), donc deux appels sur le même compte s'additionnent. Rend l'identifiant de l'équipe.
func GrantViaTeam(t testing.TB, db *sql.DB, userID, scopeType, value, mode string) string {
	t.Helper()
	teamID := uuid.New().String()
	for _, q := range []struct {
		sql  string
		args []any
	}{
		{`INSERT INTO teams (id, name) VALUES (?, ?)`, []any{teamID, "equipe-" + teamID}},
		{`INSERT INTO team_members (team_id, user_id) VALUES (?, ?)`, []any{teamID, userID}},
	} {
		if _, err := db.Exec(q.sql, q.args...); err != nil {
			t.Fatalf("%s: %v", q.sql, err)
		}
	}
	AddAccess(t, db, teamID, Access(scopeType, value, mode))
	return teamID
}

// Save enregistre un accès d'une équipe sous un identifiant donné (création ou remplacement), sans testing.T pour les
// fixtures qui rendent une erreur.
func Save(db *sql.DB, teamID, accessID string, a rbac.TeamAccess) error {
	a.ID, a.TeamID = accessID, teamID
	return rbac.SaveTeamAccess(context.Background(), db, a)
}
