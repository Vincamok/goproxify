// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"slices"
)

// Capacités : droits qui ne portent pas sur une ressource (contrairement aux grants
// domain/server/proxy/edge). Elles s'obtiennent par l'appartenance à une équipe qui les porte ;
// seul le superadmin compose une telle équipe.
const (
	// PermGDPRReveal autorise la révélation de l'IP réelle d'une entrée de log pseudonymisée.
	PermGDPRReveal = ScopeGDPRReveal
	// PermGDPRExport autorise l'export d'accès et de portabilité (RGPD Art. 15 et 20).
	PermGDPRExport = ScopeGDPRExport
	// PermGDPRErase autorise l'effacement par IP ou par utilisateur (RGPD Art. 17).
	PermGDPRErase = ScopeGDPRErase
	// PermGDPRHold autorise le gel légal et l'export signé de l'historique des logs.
	PermGDPRHold = "gdpr:hold"

	// DPOTeamID et DPOTeamName désignent l'équipe intégrée du délégué à la protection des données :
	// créée au démarrage, ni renommable ni supprimable, sans accès aux ressources, elle porte les quatre
	// capacités RGPD. Ses membres sont des comptes nommés.
	DPOTeamID   = "team-dpo"
	DPOTeamName = "DPO"
)

// KnownPermissions liste les capacités acceptées par l'API (ordre stable pour l'UI).
var KnownPermissions = []string{PermGDPRReveal, PermGDPRExport, PermGDPRErase, PermGDPRHold}

// IsKnownPermission indique si p est une capacité reconnue.
func IsKnownPermission(p string) bool { return slices.Contains(KnownPermissions, p) }

// IsBuiltInTeam indique si l'équipe est intégrée : elle ne se renomme ni ne se supprime, et sa composition seule change.
func IsBuiltInTeam(teamID string) bool { return teamID == DPOTeamID }

// EnsureBuiltInTeams crée les équipes intégrées si elles manquent et leur redonne leurs capacités. Appelée au démarrage,
// après le chargement de users.yaml.
func EnsureBuiltInTeams(ctx context.Context, db *sql.DB) error {
	if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO teams (id, name) VALUES (?, ?)`, DPOTeamID, DPOTeamName); err != nil {
		return err
	}
	var exists int
	if err := db.QueryRowContext(ctx, `SELECT COUNT(*) FROM teams WHERE id=?`, DPOTeamID).Scan(&exists); err != nil || exists == 0 {
		return err
	}
	for _, p := range KnownPermissions {
		if _, err := db.ExecContext(ctx, `INSERT OR IGNORE INTO team_permissions (team_id, permission) VALUES (?, ?)`, DPOTeamID, p); err != nil {
			return err
		}
	}
	return nil
}

// TeamPermissions retourne les capacités accordées aux membres d'une équipe.
func TeamPermissions(ctx context.Context, db *sql.DB, teamID string) []string {
	return queryPermissions(ctx, db, `SELECT permission FROM team_permissions WHERE team_id=? ORDER BY permission`, teamID)
}

// UserPermissions retourne les capacités effectives : toutes pour le superadmin, sinon celles des équipes du compte.
func UserPermissions(ctx context.Context, db *sql.DB, userID string) []string {
	role := UserRole(ctx, db, userID)
	if role == "" {
		return nil
	}
	perms := queryPermissions(ctx, db, `
		SELECT tp.permission FROM team_permissions tp
		JOIN team_members tm ON tm.team_id = tp.team_id
		WHERE tm.user_id = ?`, userID)
	if IsSuperAdminRole(role) {
		perms = append(perms, KnownPermissions...)
	}
	var out []string
	for _, p := range KnownPermissions {
		if slices.Contains(perms, p) {
			out = append(out, p)
		}
	}
	return out
}

// HasPermission indique si l'utilisateur détient la capacité, par le rôle superadmin ou par une équipe.
func HasPermission(ctx context.Context, db *sql.DB, userID, perm string) bool {
	return slices.Contains(UserPermissions(ctx, db, userID), perm)
}

// CanExerciseGDPR indique si l'utilisateur peut exercer la capacité RGPD. Un administrateur garde l'export et
// l'effacement qu'il exerçait avec les réglages des logs ; la révélation d'IP et le gel légal ne s'obtiennent que
// par l'équipe DPO (ou le superadmin).
func CanExerciseGDPR(ctx context.Context, db *sql.DB, userID, perm string) bool {
	if HasPermission(ctx, db, userID, perm) {
		return true
	}
	return (perm == PermGDPRExport || perm == PermGDPRErase) && IsAdmin(ctx, db, userID)
}

// IsProtectedAccount indique si seul un superadmin peut modifier, réinitialiser ou supprimer
// ce compte : superadmin ou détenteur d'une capacité. Sinon un admin pourrait en changer le
// mot de passe et s'en servir pour exercer un droit qui lui est refusé.
func IsProtectedAccount(ctx context.Context, db *sql.DB, userID string) bool {
	return IsSuperAdmin(ctx, db, userID) || len(UserPermissions(ctx, db, userID)) > 0
}

// NormalizePermissions ne garde que les capacités connues, sans doublon, dans l'ordre de
// KnownPermissions. ok vaut false si une capacité inconnue a été fournie.
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
