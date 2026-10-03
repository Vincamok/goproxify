// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"slices"
)

// Permissions de capacité : droits qui ne portent pas sur une ressource (contrairement aux
// grants domain/server/proxy/edge) et que seul le superadmin accorde.
const (
	// PermGDPRReveal autorise la révélation de l'IP réelle d'une entrée de log pseudonymisée.
	PermGDPRReveal = ScopeGDPRReveal

	// RoleDPO est le rôle plateforme du délégué à la protection des données : droits d'un
	// compte user, plus PermGDPRReveal.
	RoleDPO = "dpo"
)

// KnownPermissions liste les permissions acceptées par l'API (ordre stable pour l'UI).
var KnownPermissions = []string{PermGDPRReveal}

// IsKnownPermission indique si p est une permission reconnue.
func IsKnownPermission(p string) bool { return slices.Contains(KnownPermissions, p) }

// rolePermissions retourne les permissions qu'un rôle porte par lui-même.
func rolePermissions(role string) []string {
	switch role {
	case "superadmin":
		return KnownPermissions
	case RoleDPO:
		return []string{PermGDPRReveal}
	}
	return nil
}

// DirectPermissions retourne les permissions accordées en propre à l'utilisateur.
func DirectPermissions(ctx context.Context, db *sql.DB, userID string) []string {
	return queryPermissions(ctx, db, `SELECT permission FROM user_permissions WHERE user_id=? ORDER BY permission`, userID)
}

// TeamPermissions retourne les permissions accordées aux membres d'une équipe.
func TeamPermissions(ctx context.Context, db *sql.DB, teamID string) []string {
	return queryPermissions(ctx, db, `SELECT permission FROM team_permissions WHERE team_id=? ORDER BY permission`, teamID)
}

// UserPermissions retourne les permissions effectives : rôle, accordées en propre et via les équipes.
func UserPermissions(ctx context.Context, db *sql.DB, userID string) []string {
	role := UserRole(ctx, db, userID)
	if role == "" {
		return nil
	}
	perms := slices.Clone(rolePermissions(role))
	perms = append(perms, DirectPermissions(ctx, db, userID)...)
	perms = append(perms, queryPermissions(ctx, db, `
		SELECT tp.permission FROM team_permissions tp
		JOIN team_members tm ON tm.team_id = tp.team_id
		WHERE tm.user_id = ?`, userID)...)
	var out []string
	for _, p := range KnownPermissions {
		if slices.Contains(perms, p) {
			out = append(out, p)
		}
	}
	return out
}

// HasPermission indique si l'utilisateur détient la permission, par quelque voie que ce soit.
func HasPermission(ctx context.Context, db *sql.DB, userID, perm string) bool {
	return slices.Contains(UserPermissions(ctx, db, userID), perm)
}

// IsProtectedAccount indique si seul un superadmin peut modifier, réinitialiser ou supprimer
// ce compte : superadmin ou détenteur d'une permission. Sinon un admin pourrait en changer le
// mot de passe et s'en servir pour exercer un droit qui lui est refusé.
func IsProtectedAccount(ctx context.Context, db *sql.DB, userID string) bool {
	return IsSuperAdmin(ctx, db, userID) || len(UserPermissions(ctx, db, userID)) > 0
}

// NormalizePermissions ne garde que les permissions connues, sans doublon, dans l'ordre de
// KnownPermissions. ok vaut false si une permission inconnue a été fournie.
func NormalizePermissions(perms []string) (out []string, ok bool) {
	ok = true
	for _, p := range perms {
		if !IsKnownPermission(p) {
			ok = false
		}
	}
	for _, p := range KnownPermissions {
		if slices.Contains(perms, p) {
			out = append(out, p)
		}
	}
	return out, ok
}

func queryPermissions(ctx context.Context, db *sql.DB, q string, arg string) []string {
	rows, err := db.QueryContext(ctx, q, arg)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var p string
		if rows.Scan(&p) == nil {
			out = append(out, p)
		}
	}
	return out
}
