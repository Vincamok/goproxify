// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
)

// AccessTeam est une équipe du compte avec ce qu'elle lui apporte.
type AccessTeam struct {
	ID          string       `json:"id"`
	Name        string       `json:"name"`
	Builtin     bool         `json:"builtin,omitempty"`
	Accesses    []TeamAccess `json:"accesses"`
	Permissions []string     `json:"permissions"`
}

// AccessPermission est une capacité avec son origine : le rôle du compte, ou les équipes qui la portent.
type AccessPermission struct {
	Permission string   `json:"permission"`
	ViaRole    string   `json:"via_role,omitempty"`
	ViaTeams   []string `json:"via_teams,omitempty"`
}

// Access est l'accès effectif d'un compte et l'origine de chaque droit : la seule définition, que l'interface affiche.
type Access struct {
	Role string `json:"role"`
	// Global : le compte est administrateur, il voit toute la plateforme ; ses équipes ne le restreignent ni ne l'étendent.
	Global      bool               `json:"global"`
	Teams       []AccessTeam       `json:"teams"`
	Permissions []AccessPermission `json:"permissions"`
	// Granted liste les permissions du catalogue que portent les accès de ses équipes (aucune pour un administrateur,
	// qui les détient toutes) : ce que la navigation lit pour montrer ou cacher une page.
	Granted []string `json:"granted"`
}

// EffectiveAccess calcule l'accès effectif d'un compte : ses équipes avec leurs accès, les permissions du catalogue qui
// en découlent et ses capacités avec leur origine.
func EffectiveAccess(ctx context.Context, db *sql.DB, userID string) (Access, error) {
	role := UserRole(ctx, db, userID)
	out := Access{Role: role, Global: IsAdminRole(role), Teams: []AccessTeam{}, Permissions: []AccessPermission{}, Granted: []string{}}

	rows, err := db.QueryContext(ctx, `
		SELECT t.id, t.name FROM team_members tm
		JOIN teams t ON t.id = tm.team_id
		WHERE tm.user_id = ? ORDER BY t.name`, userID)
	if err != nil {
		return out, err
	}
	for rows.Next() {
		var t AccessTeam
		if rows.Scan(&t.ID, &t.Name) == nil {
			t.Builtin = IsBuiltInTeam(t.ID)
			out.Teams = append(out.Teams, t)
		}
	}
	rows.Close()

	teamsOf := map[string][]string{} // capacité → équipes
	var all []TeamAccess
	for i := range out.Teams {
		t := &out.Teams[i]
		if t.Accesses, err = TeamAccesses(ctx, db, t.ID); err != nil {
			return out, err
		}
		all = append(all, t.Accesses...)
		t.Permissions = TeamPermissions(ctx, db, t.ID)
		if t.Permissions == nil {
			t.Permissions = []string{}
		}
		for _, p := range t.Permissions {
			teamsOf[p] = append(teamsOf[p], t.Name)
		}
	}
	if !out.Global {
		for _, p := range Permissions() {
			for _, a := range all {
				if a.Grants(p.ID) {
					out.Granted = append(out.Granted, p.ID)
					break
				}
			}
		}
	}

	for _, p := range KnownPermissions {
		ap := AccessPermission{Permission: p, ViaTeams: teamsOf[p]}
		switch {
		case IsSuperAdminRole(role):
			ap.ViaRole = "superadmin"
		case IsAdminRole(role) && (p == PermGDPRExport || p == PermGDPRErase):
			ap.ViaRole = "admin"
		}
		if ap.ViaRole != "" || len(ap.ViaTeams) > 0 {
			out.Permissions = append(out.Permissions, ap)
		}
	}
	return out, nil
}
