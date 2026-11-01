// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
	"slices"
	"strings"
	"unicode"
)

// Accès d'équipe (ADR 0022, section 1) : un périmètre et, pour chaque service, un niveau. Les niveaux d'un service sont
// cumulatifs : « Exploitation » comprend « Lecture ». Les permissions sensibles se cochent à part. Une équipe a
// plusieurs accès, dont les droits s'additionnent.

// TeamAccess est un accès d'une équipe.
type TeamAccess struct {
	ID          string            `json:"id"`
	TeamID      string            `json:"team_id,omitempty"`
	Name        string            `json:"name"`
	Perimeter   Perimeter         `json:"perimeter"`
	Levels      map[string]string `json:"levels"`
	Permissions []string          `json:"permissions"`
}

const maxAccessNameLen = 80

// notGrantable sont les permissions explicites qu'une équipe ne reçoit pas par la grille : les capacités RGPD ont
// leur équipe intégrée, et accorder des droits à d'autres est réservé à l'administrateur.
var notGrantable = []string{PermGDPRReveal, PermGDPRExport, PermGDPRErase, PermGDPRHold, "users:write", "teams:write"}

// Validate vérifie un accès avant son enregistrement : périmètre évaluable, services et niveaux connus, aucun niveau
// d'écriture de plateforme (objets partagés), permissions explicites accordables.
func (a TeamAccess) Validate() error {
	name := strings.TrimSpace(a.Name)
	if len(name) > maxAccessNameLen {
		return fmt.Errorf("nom : %d caractères au plus", maxAccessNameLen)
	}
	if strings.IndexFunc(name, unicode.IsControl) >= 0 {
		return fmt.Errorf("nom : caractères de contrôle interdits")
	}
	if err := a.Perimeter.Validate(); err != nil {
		return err
	}
	for service, level := range a.Levels {
		svc, ok := ServiceByID(service)
		if !ok {
			return fmt.Errorf("service %q inconnu", service)
		}
		i := levelIndex(svc, level)
		if i < 0 {
			return fmt.Errorf("service %q : niveau %q inconnu", service, level)
		}
		if svc.Levels[i].Class == ClassPlatform {
			return fmt.Errorf("service %q : l'écriture est réservée à l'administrateur de la plateforme", service)
		}
	}
	seen := map[string]bool{}
	for _, id := range a.Permissions {
		p, ok := PermissionByID(id)
		if !ok {
			return fmt.Errorf("permission %q inconnue", id)
		}
		if p.Class != ClassSensitive {
			return fmt.Errorf("permission %q : elle fait partie d'un niveau, pas d'une case à cocher", id)
		}
		if slices.Contains(notGrantable, id) {
			return fmt.Errorf("permission %q : elle ne s'accorde pas par la grille", id)
		}
		if seen[id] {
			return fmt.Errorf("permission %q en double", id)
		}
		seen[id] = true
	}
	return nil
}

func levelIndex(svc Service, level string) int {
	return slices.IndexFunc(svc.Levels, func(l Level) bool { return l.ID == level })
}

// Grants dit si l'accès porte la permission : le niveau choisi pour son service est au moins aussi haut, ou la
// permission explicite est cochée. L'écriture d'un objet partagé n'est jamais accordée.
func (a TeamAccess) Grants(permission string) bool {
	p, ok := PermissionByID(permission)
	if !ok {
		return false
	}
	if p.Class == ClassPlatform {
		return false
	}
	if p.Class == ClassSensitive {
		return slices.Contains(a.Permissions, permission)
	}
	svc, _ := ServiceByID(p.Service)
	chosen, ok := a.Levels[p.Service]
	if !ok {
		return false
	}
	want := levelIndex(svc, strings.TrimPrefix(permission, p.Service+":"))
	have := levelIndex(svc, chosen)
	return have >= 0 && want >= 0 && have >= want
}

// UserAccesses rend les accès de toutes les équipes du compte.
func UserAccesses(ctx context.Context, db *sql.DB, userID string) ([]TeamAccess, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT a.id, a.team_id, a.name, a.perimeter, a.levels, a.permissions
		FROM team_accesses a
		JOIN team_members tm ON tm.team_id = a.team_id
		WHERE tm.user_id = ?
		ORDER BY a.team_id, a.position, a.id`, userID)
	if err != nil {
		return nil, err
	}
	return scanAccesses(rows)
}

// TeamAccesses rend les accès d'une équipe, dans l'ordre où ils ont été créés.
func TeamAccesses(ctx context.Context, db *sql.DB, teamID string) ([]TeamAccess, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT id, team_id, name, perimeter, levels, permissions
		FROM team_accesses WHERE team_id = ? ORDER BY position, id`, teamID)
	if err != nil {
		return nil, err
	}
	return scanAccesses(rows)
}

func scanAccesses(rows *sql.Rows) ([]TeamAccess, error) {
	defer rows.Close()
	out := []TeamAccess{}
	for rows.Next() {
		var a TeamAccess
		var perimeter, levels, permissions string
		if err := rows.Scan(&a.ID, &a.TeamID, &a.Name, &perimeter, &levels, &permissions); err != nil {
			return nil, err
		}
		_ = json.Unmarshal([]byte(perimeter), &a.Perimeter)
		_ = json.Unmarshal([]byte(levels), &a.Levels)
		_ = json.Unmarshal([]byte(permissions), &a.Permissions)
		if a.Levels == nil {
			a.Levels = map[string]string{}
		}
		if a.Permissions == nil {
			a.Permissions = []string{}
		}
		out = append(out, a)
	}
	return out, rows.Err()
}

// SaveTeamAccess enregistre un accès (création si l'identifiant n'existe pas pour l'équipe, remplacement sinon).
func SaveTeamAccess(ctx context.Context, db *sql.DB, a TeamAccess) error {
	a.Name = strings.TrimSpace(a.Name)
	if err := a.Validate(); err != nil {
		return err
	}
	if a.Levels == nil {
		a.Levels = map[string]string{}
	}
	if a.Permissions == nil {
		a.Permissions = []string{}
	}
	perimeter, _ := json.Marshal(a.Perimeter)
	levels, _ := json.Marshal(a.Levels)
	permissions, _ := json.Marshal(a.Permissions)
	res, err := db.ExecContext(ctx,
		`UPDATE team_accesses SET name=?, perimeter=?, levels=?, permissions=? WHERE id=? AND team_id=?`,
		a.Name, string(perimeter), string(levels), string(permissions), a.ID, a.TeamID)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n > 0 {
		return nil
	}
	_, err = db.ExecContext(ctx, `
		INSERT INTO team_accesses (id, team_id, name, perimeter, levels, permissions, position)
		VALUES (?, ?, ?, ?, ?, ?, (SELECT COALESCE(MAX(position), 0) + 1 FROM team_accesses WHERE team_id = ?))`,
		a.ID, a.TeamID, a.Name, string(perimeter), string(levels), string(permissions), a.TeamID)
	return err
}

// DeleteTeamAccess supprime un accès d'une équipe ; faux s'il n'existe pas.
func DeleteTeamAccess(ctx context.Context, db *sql.DB, teamID, accessID string) (bool, error) {
	res, err := db.ExecContext(ctx, `DELETE FROM team_accesses WHERE id=? AND team_id=?`, accessID, teamID)
	if err != nil {
		return false, err
	}
	n, _ := res.RowsAffected()
	return n > 0, nil
}

// Access renvoie l'accès que remplit le profil, sans périmètre ni nom.
func (p Profile) Access() TeamAccess {
	levels := map[string]string{}
	for k, v := range p.Levels {
		levels[k] = v
	}
	return TeamAccess{Name: p.Label, Levels: levels, Permissions: append([]string{}, p.Permissions...)}
}
