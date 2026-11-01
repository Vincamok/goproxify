// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"sort"
)

// AccessTeam est une équipe du compte avec ce qu'elle lui apporte.
type AccessTeam struct {
	ID          string   `json:"id"`
	Name        string   `json:"name"`
	Builtin     bool     `json:"builtin,omitempty"`
	Scopes      []Grant  `json:"scopes"`
	Permissions []string `json:"permissions"`
}

// AccessGrant est un accès sur les ressources, avec les équipes qui l'accordent. Le mode le plus haut l'emporte.
type AccessGrant struct {
	Type       string   `json:"type"`
	Value      string   `json:"value"`
	AccessMode string   `json:"access_mode"`
	Teams      []string `json:"teams"`
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
	Grants      []AccessGrant      `json:"grants"`
	Permissions []AccessPermission `json:"permissions"`
}

// EffectiveAccess calcule l'accès effectif d'un compte : ses équipes, les accès qu'elles accordent (fusionnés, le mode
// écriture l'emporte) et ses capacités avec leur origine.
func EffectiveAccess(ctx context.Context, db *sql.DB, userID string) (Access, error) {
	role := UserRole(ctx, db, userID)
	out := Access{Role: role, Global: IsAdminRole(role), Teams: []AccessTeam{}, Grants: []AccessGrant{}, Permissions: []AccessPermission{}}

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

	merged := map[string]*AccessGrant{}
	var order []string
	teamsOf := map[string][]string{} // permission → équipes
	for i := range out.Teams {
		t := &out.Teams[i]
		t.Scopes = []Grant{}
		srows, err := db.QueryContext(ctx,
			`SELECT scope_type, scope_value, access_mode FROM team_scopes WHERE team_id=? ORDER BY scope_type, scope_value`, t.ID)
		if err != nil {
			return out, err
		}
		for srows.Next() {
			var g Grant
			if srows.Scan(&g.Type, &g.Value, &g.Mode) != nil {
				continue
			}
			if g.Mode != AccessWrite {
				g.Mode = AccessRead
			}
			t.Scopes = append(t.Scopes, g)
			key := g.Type + "\x00" + g.Value
			ag, ok := merged[key]
			if !ok {
				ag = &AccessGrant{Type: g.Type, Value: g.Value, AccessMode: g.Mode}
				merged[key] = ag
				order = append(order, key)
			}
			if g.Mode == AccessWrite {
				ag.AccessMode = AccessWrite
			}
			ag.Teams = append(ag.Teams, t.Name)
		}
		srows.Close()
		t.Permissions = TeamPermissions(ctx, db, t.ID)
		if t.Permissions == nil {
			t.Permissions = []string{}
		}
		for _, p := range t.Permissions {
			teamsOf[p] = append(teamsOf[p], t.Name)
		}
	}
	if !out.Global {
		sort.Strings(order)
		for _, key := range order {
			out.Grants = append(out.Grants, *merged[key])
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
