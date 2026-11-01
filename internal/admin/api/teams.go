// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"slices"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// TeamsHandler gère le CRUD des équipes et de leurs membres/scopes.
// Toutes les opérations d'écriture sont réservées aux administrateurs globaux
// (le middleware RequireAdmin est appliqué dans server.go).
type TeamsHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	OnChange func()
}

func (h *TeamsHandler) notifyChange() {
	if h.OnChange != nil {
		go h.OnChange()
	}
}

func (h *TeamsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	p := strings.TrimPrefix(r.URL.Path, "/api/v1/teams")
	p = strings.TrimPrefix(p, "/")
	parts := strings.SplitN(p, "/", 3)
	id := parts[0]
	sub := ""
	subID := ""
	if len(parts) > 1 {
		sub = parts[1]
	}
	if len(parts) > 2 {
		subID = parts[2]
	}

	switch {
	// Équipes
	case r.Method == http.MethodGet && id == "":
		h.listTeams(w, r)
	case r.Method == http.MethodPost && id == "":
		h.createTeam(w, r)
	case r.Method == http.MethodGet && id != "" && sub == "":
		h.getTeam(w, r, id)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.updateTeam(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.deleteTeam(w, r, id)
	// Membres
	case r.Method == http.MethodGet && sub == "members":
		h.listMembers(w, r, id)
	case r.Method == http.MethodPost && sub == "members":
		h.addMember(w, r, id)
	case r.Method == http.MethodDelete && sub == "members" && subID != "":
		h.removeMember(w, r, id, subID)
	// Permissions (superadmin)
	case r.Method == http.MethodGet && sub == "permissions":
		jsonOK(w, map[string][]string{"permissions": orEmpty(rbac.TeamPermissions(r.Context(), h.DB, id))})
	case r.Method == http.MethodPut && sub == "permissions":
		h.setPermissions(w, r, id)
	// Accès (périmètre + niveau par service)
	case r.Method == http.MethodGet && sub == "accesses":
		h.listAccesses(w, r, id)
	case r.Method == http.MethodPost && sub == "accesses" && subID == "":
		h.saveAccess(w, r, id, "")
	case r.Method == http.MethodPut && sub == "accesses" && subID != "":
		h.saveAccess(w, r, id, subID)
	case r.Method == http.MethodDelete && sub == "accesses" && subID != "":
		h.removeAccess(w, r, id, subID)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

// --- Équipes ---

type teamRow struct {
	ID          string    `json:"id"`
	Name        string    `json:"name"`
	CreatedAt   time.Time `json:"created_at"`
	MemberCount int       `json:"member_count"`
	AccessCount int       `json:"access_count"`
	Permissions []string  `json:"permissions"`
	// Builtin : équipe intégrée (DPO) ; seule sa composition change, par le superadmin.
	Builtin bool `json:"builtin,omitempty"`
}

// refuseBuiltin répond 409 pour une équipe intégrée : elle ne se renomme ni ne se supprime, n'a aucun accès sur les
// ressources et ses capacités sont fixes.
func refuseBuiltin(w http.ResponseWriter, r *http.Request, teamID string) bool {
	if !rbac.IsBuiltInTeam(teamID) {
		return false
	}
	writeErr(w, r, http.StatusConflict, "api.err.builtin_team")
	return true
}

// setPermissions remplace les permissions accordées aux membres de l'équipe (superadmin).
func (h *TeamsHandler) setPermissions(w http.ResponseWriter, r *http.Request, teamID string) {
	if refuseBuiltin(w, r, teamID) {
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	if !rbac.IsSuperAdmin(r.Context(), h.DB, actor) {
		writeErr(w, r, http.StatusForbidden, "api.err.superadmin_required")
		return
	}
	var req struct {
		Permissions []string `json:"permissions"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	perms, ok := rbac.NormalizePermissions(req.Permissions)
	if !ok {
		writeErr(w, r, http.StatusBadRequest, "api.err.unknown_permission")
		return
	}
	var exists int
	h.DB.QueryRowContext(r.Context(), `SELECT COUNT(*) FROM teams WHERE id=?`, teamID).Scan(&exists) //nolint:errcheck
	if exists == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `DELETE FROM team_permissions WHERE team_id=?`, teamID); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	for _, p := range perms {
		if _, err := h.DB.ExecContext(r.Context(),
			`INSERT INTO team_permissions (team_id, permission) VALUES (?, ?)`, teamID, p); err != nil {
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
	}
	_ = admindb.WriteAudit(h.DB, actor, "set_permissions", "team:"+teamID, "permissions="+strings.Join(perms, ","))
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamsHandler) listTeams(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT t.id, t.name, t.created_at,
		       (SELECT COUNT(*) FROM team_members WHERE team_id=t.id) as member_count,
		       (SELECT COUNT(*) FROM team_accesses WHERE team_id=t.id) as access_count
		FROM teams t ORDER BY t.name`)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]teamRow, 0)
	for rows.Next() {
		var t teamRow
		if err := rows.Scan(&t.ID, &t.Name, &t.CreatedAt, &t.MemberCount, &t.AccessCount); err == nil {
			t.Builtin = rbac.IsBuiltInTeam(t.ID)
			result = append(result, t)
		}
	}
	rows.Close()
	for i := range result {
		result[i].Permissions = orEmpty(rbac.TeamPermissions(r.Context(), h.DB, result[i].ID))
	}
	jsonOK(w, result)
}

func (h *TeamsHandler) createTeam(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	t := teamRow{ID: uuid.New().String(), Name: req.Name}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO teams (id, name) VALUES (?, ?)`, t.ID, t.Name); err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "team:"+t.ID, t.Name)
	h.notifyChange()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(t)
}

func (h *TeamsHandler) getTeam(w http.ResponseWriter, r *http.Request, id string) {
	var t teamRow
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, created_at FROM teams WHERE id=?`, id).Scan(&t.ID, &t.Name, &t.CreatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	t.Permissions = orEmpty(rbac.TeamPermissions(r.Context(), h.DB, id))
	t.Builtin = rbac.IsBuiltInTeam(t.ID)
	jsonOK(w, t)
}

func (h *TeamsHandler) updateTeam(w http.ResponseWriter, r *http.Request, id string) {
	if refuseBuiltin(w, r, id) {
		return
	}
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE teams SET name=? WHERE id=?`, req.Name, id)
	if err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "team:"+id, req.Name)
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamsHandler) deleteTeam(w http.ResponseWriter, r *http.Request, id string) {
	if refuseBuiltin(w, r, id) {
		return
	}
	if !h.guardTeamPermissions(w, r, id) {
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM teams WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.team_not_found")
		return
	}
	// Cascade manuelle (SQLite sans FK activées)
	h.DB.ExecContext(r.Context(), `DELETE FROM team_members WHERE team_id=?`, id)     //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM team_accesses WHERE team_id=?`, id)    //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM team_permissions WHERE team_id=?`, id) //nolint:errcheck
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "team:"+id, "")
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

// --- Membres ---

type memberRow struct {
	UserID string `json:"user_id"`
	Email  string `json:"email"`
}

func (h *TeamsHandler) listMembers(w http.ResponseWriter, r *http.Request, teamID string) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT tm.user_id, u.email
		FROM team_members tm
		JOIN users u ON u.id = tm.user_id
		WHERE tm.team_id = ?
		ORDER BY u.email`, teamID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	result := make([]memberRow, 0)
	for rows.Next() {
		var m memberRow
		if err := rows.Scan(&m.UserID, &m.Email); err == nil {
			result = append(result, m)
		}
	}
	jsonOK(w, result)
}

// guardTeamPermissions refuse (403) qu'un non-superadmin change la composition d'une équipe
// qui porte une permission : ce serait accorder ou retirer cette permission.
func (h *TeamsHandler) guardTeamPermissions(w http.ResponseWriter, r *http.Request, teamID string) bool {
	if len(rbac.TeamPermissions(r.Context(), h.DB, teamID)) > 0 &&
		!rbac.IsSuperAdmin(r.Context(), h.DB, adminauth.UserIDFromContext(r.Context())) {
		writeErr(w, r, http.StatusForbidden, "api.err.superadmin_required")
		return false
	}
	return true
}

func (h *TeamsHandler) addMember(w http.ResponseWriter, r *http.Request, teamID string) {
	var req struct {
		UserID string `json:"user_id"`
		Role   string `json:"role"` // ignoré (compat) — héritage intégral des grants équipe
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.UserID == "" {
		http.Error(w, "user_id requis", http.StatusBadRequest)
		return
	}
	if !h.guardTeamPermissions(w, r, teamID) {
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT OR REPLACE INTO team_members (team_id, user_id) VALUES (?, ?)`,
		teamID, req.UserID); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "add_member", "team:"+teamID, req.UserID)
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *TeamsHandler) removeMember(w http.ResponseWriter, r *http.Request, teamID, userID string) {
	if !h.guardTeamPermissions(w, r, teamID) {
		return
	}
	res, err := h.DB.ExecContext(r.Context(),
		`DELETE FROM team_members WHERE team_id=? AND user_id=?`, teamID, userID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "membre introuvable", http.StatusNotFound)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "remove_member", "team:"+teamID, userID)
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

// --- Accès ---

func (h *TeamsHandler) listAccesses(w http.ResponseWriter, r *http.Request, teamID string) {
	accesses, err := rbac.TeamAccesses(r.Context(), h.DB, teamID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, accesses)
}

// saveAccess crée (POST) ou remplace (PUT) un accès de l'équipe. Corps : name, perimeter, levels (service → niveau),
// permissions (cases à cocher sensibles). Un refus de validation répond 400 avec la raison.
func (h *TeamsHandler) saveAccess(w http.ResponseWriter, r *http.Request, teamID, accessID string) {
	if refuseBuiltin(w, r, teamID) {
		return
	}
	var a rbac.TeamAccess
	if err := json.NewDecoder(r.Body).Decode(&a); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	created := accessID == ""
	if created {
		accessID = uuid.New().String()
	} else if existing, _ := rbac.TeamAccesses(r.Context(), h.DB, teamID); !slices.ContainsFunc(existing, func(e rbac.TeamAccess) bool { return e.ID == accessID }) {
		http.Error(w, "accès introuvable", http.StatusNotFound)
		return
	}
	a.ID, a.TeamID = accessID, teamID
	if err := rbac.SaveTeamAccess(r.Context(), h.DB, a); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	a.Name = strings.TrimSpace(a.Name)
	action := "update_access"
	if created {
		action = "add_access"
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, action, "team:"+teamID, a.ID+" "+a.Name)
	h.notifyChange()
	if created {
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		_ = json.NewEncoder(w).Encode(a)
		return
	}
	jsonOK(w, a)
}

func (h *TeamsHandler) removeAccess(w http.ResponseWriter, r *http.Request, teamID, accessID string) {
	ok, err := rbac.DeleteTeamAccess(r.Context(), h.DB, teamID, accessID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if !ok {
		http.Error(w, "accès introuvable", http.StatusNotFound)
		return
	}
	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "remove_access", "team:"+teamID, accessID)
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}
