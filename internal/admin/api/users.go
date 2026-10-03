// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
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

// UsersHandler gère le CRUD des utilisateurs.
type UsersHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	OnChange func() // appelé après create/update/delete
}

func (h *UsersHandler) notifyChange() {
	if h.OnChange != nil {
		go h.OnChange()
	}
}

func (h *UsersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/users")
	path = strings.TrimPrefix(path, "/")
	parts := strings.SplitN(path, "/", 2)
	id := parts[0]
	sub := ""
	if len(parts) > 1 {
		sub = parts[1]
	}

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodGet && id != "" && sub == "":
		h.get(w, r, id)
	case r.Method == http.MethodPut && id != "" && sub == "":
		h.update(w, r, id)
	case r.Method == http.MethodPut && id != "" && sub == "password":
		h.changePassword(w, r, id)
	case r.Method == http.MethodDelete && id != "" && sub == "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

type userRow struct {
	ID        string    `json:"id"`
	Email     string    `json:"email"`
	Role      string    `json:"role"`
	CreatedAt time.Time `json:"created_at"`
	TeamNames string    `json:"team_names,omitempty"`
	// Permissions : accordées en propre ; EffectivePermissions : y compris rôle et équipes.
	Permissions          []string `json:"permissions"`
	EffectivePermissions []string `json:"effective_permissions"`
}

type userTeam struct {
	TeamID string `json:"team_id"`
}

type userScope struct {
	ID          string `json:"id,omitempty"`
	ScopeType   string `json:"scope_type"`
	Value       string `json:"value"`
	AccessMode  string `json:"access_mode"`
}

type userDetail struct {
	ID                   string      `json:"id"`
	Email                string      `json:"email"`
	Role                 string      `json:"role"`
	CreatedAt            time.Time   `json:"created_at"`
	Teams                []userTeam  `json:"teams"`
	Scopes               []userScope `json:"scopes"`
	Permissions          []string    `json:"permissions"`
	EffectivePermissions []string    `json:"effective_permissions"`
}

// orEmpty évite un null JSON pour une liste vide.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func replaceUserPermissions(db *sql.DB, userID string, perms []string) error {
	if _, err := db.Exec(`DELETE FROM user_permissions WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, p := range perms {
		if _, err := db.Exec(`INSERT INTO user_permissions (user_id, permission) VALUES (?, ?)`, userID, p); err != nil {
			return err
		}
	}
	return nil
}

func (h *UsersHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `
		SELECT u.id, u.email, u.role, u.created_at,
		       COALESCE(GROUP_CONCAT(t.name, ', '),'') as team_names
		FROM users u
		LEFT JOIN team_members tm ON tm.user_id = u.id
		LEFT JOIN teams t ON t.id = tm.team_id
		GROUP BY u.id
		ORDER BY u.created_at DESC`)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: list", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]userRow, 0)
	for rows.Next() {
		var u userRow
		if err := rows.Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt, &u.TeamNames); err != nil {
			continue
		}
		result = append(result, u)
	}
	rows.Close()
	for i := range result {
		result[i].Permissions = orEmpty(rbac.DirectPermissions(r.Context(), h.DB, result[i].ID))
		result[i].EffectivePermissions = orEmpty(rbac.UserPermissions(r.Context(), h.DB, result[i].ID))
	}
	jsonOK(w, result)
}

func (h *UsersHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var u userRow
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, email, role, created_at FROM users WHERE id=?`, id).
		Scan(&u.ID, &u.Email, &u.Role, &u.CreatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: get", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	trows, _ := h.DB.QueryContext(r.Context(),
		`SELECT team_id FROM team_members WHERE user_id=? ORDER BY team_id`, id)
	teams := make([]userTeam, 0)
	if trows != nil {
		defer trows.Close()
		for trows.Next() {
			var tm userTeam
			if err := trows.Scan(&tm.TeamID); err == nil {
				teams = append(teams, tm)
			}
		}
	}

	scopes := listUserScopes(h.DB, r, id)
	jsonOK(w, userDetail{ID: u.ID, Email: u.Email, Role: u.Role, CreatedAt: u.CreatedAt, Teams: teams, Scopes: scopes,
		Permissions:          orEmpty(rbac.DirectPermissions(r.Context(), h.DB, id)),
		EffectivePermissions: orEmpty(rbac.UserPermissions(r.Context(), h.DB, id)),
	})
}

func listUserScopes(db *sql.DB, r *http.Request, userID string) []userScope {
	rows, err := db.QueryContext(r.Context(),
		`SELECT id, scope_type, scope_value, access_mode FROM user_scopes WHERE user_id=? ORDER BY scope_type, scope_value`, userID)
	out := make([]userScope, 0)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		var s userScope
		if err := rows.Scan(&s.ID, &s.ScopeType, &s.Value, &s.AccessMode); err == nil {
			out = append(out, s)
		}
	}
	return out
}

func normalizePlatformRole(role string) (string, bool) {
	switch role {
	case "admin", "user", rbac.RoleDPO:
		return role, true
	case "operator", "viewer":
		return "user", true // compat douce
	case "superadmin":
		return "superadmin", false // non assignable via API
	default:
		return "", false
	}
}

func normalizeAccessMode(mode string) string {
	if mode == "write" {
		return "write"
	}
	return "read"
}

func replaceUserScopes(db *sql.DB, userID string, scopes []userScope) error {
	if _, err := db.Exec(`DELETE FROM user_scopes WHERE user_id=?`, userID); err != nil {
		return err
	}
	for _, s := range scopes {
		if s.ScopeType != "domain" && s.ScopeType != "server" && s.ScopeType != "proxy" && s.ScopeType != "edge" {
			continue
		}
		if s.Value == "" {
			continue
		}
		id := s.ID
		if id == "" {
			id = uuid.New().String()
		}
		if _, err := db.Exec(
			`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?, ?, ?, ?, ?)`,
			id, userID, s.ScopeType, s.Value, normalizeAccessMode(s.AccessMode),
		); err != nil {
			return err
		}
	}
	return nil
}

type updateUserRequest struct {
	Email       string       `json:"email"`
	Role        string       `json:"role"`
	Password    string       `json:"password"`
	Scopes      *[]userScope `json:"scopes"`
	Permissions *[]string    `json:"permissions"`
}

// actorIsSuper indique si l'auteur de la requête est le superadmin.
func (h *UsersHandler) actorIsSuper(r *http.Request) bool {
	return rbac.IsSuperAdmin(r.Context(), h.DB, adminauth.UserIDFromContext(r.Context()))
}

// guardProtected refuse (403) qu'un non-superadmin agisse sur un compte protégé.
func (h *UsersHandler) guardProtected(w http.ResponseWriter, r *http.Request, id string) bool {
	if !h.actorIsSuper(r) && rbac.IsProtectedAccount(r.Context(), h.DB, id) {
		writeErr(w, r, http.StatusForbidden, "api.err.protected_account")
		return false
	}
	return true
}

// grantChange indique si la requête attribue ou retire une permission : rôle dpo gagné ou
// perdu, ou permissions en propre modifiées. Réservé au superadmin.
func grantChange(r *http.Request, db *sql.DB, id, oldRole, newRole string, perms *[]string, newPerms []string) bool {
	if (oldRole == rbac.RoleDPO) != (newRole == rbac.RoleDPO) {
		return true
	}
	return perms != nil && !slices.Equal(newPerms, rbac.DirectPermissions(r.Context(), db, id))
}

func (h *UsersHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req updateUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.Email == "" {
		http.Error(w, "email requis", http.StatusBadRequest)
		return
	}

	var currentRole string
	err := h.DB.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, id).Scan(&currentRole)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: update lookup", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	if !h.guardProtected(w, r, id) {
		return
	}

	role := currentRole
	if currentRole == "superadmin" {
		// Superadmin : email / mdp / grants OK ; rôle plateforme immuable.
		role = "superadmin"
	} else {
		normalized, ok := normalizePlatformRole(req.Role)
		if !ok || normalized == "superadmin" {
			writeErr(w, r, http.StatusBadRequest, "api.err.role_admin_user")
			return
		}
		role = normalized
	}
	var perms []string
	if req.Permissions != nil {
		var ok bool
		if perms, ok = rbac.NormalizePermissions(*req.Permissions); !ok {
			writeErr(w, r, http.StatusBadRequest, "api.err.unknown_permission")
			return
		}
	}
	permsChanged := grantChange(r, h.DB, id, currentRole, role, req.Permissions, perms)
	if permsChanged && !h.actorIsSuper(r) {
		writeErr(w, r, http.StatusForbidden, "api.err.superadmin_required")
		return
	}

	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET email=?, role=? WHERE id=?`, req.Email, role, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: update", "err", err)
		}
		writeErr(w, r, http.StatusConflict, "api.err.email_taken")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}

	if req.Password != "" {
		hash, err := adminauth.HashPassword(req.Password)
		if err == nil {
			h.DB.ExecContext(r.Context(), `UPDATE users SET password_hash=? WHERE id=?`, hash, id) //nolint:errcheck
		}
	}

	if req.Scopes != nil {
		if err := replaceUserScopes(h.DB, id, *req.Scopes); err != nil {
			if !isCtxErr(err) {
				h.Log.Error("users: update scopes", "err", err)
			}
			http.Error(w, "erreur scopes", http.StatusInternalServerError)
			return
		}
	}
	if req.Permissions != nil {
		if err := replaceUserPermissions(h.DB, id, perms); err != nil {
			h.Log.Error("users: update permissions", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "user:"+id, req.Email)
	if permsChanged {
		_ = admindb.WriteAudit(h.DB, actor, "set_permissions", "user:"+id,
			fmt.Sprintf("role=%s permissions=%s", role, strings.Join(rbac.DirectPermissions(r.Context(), h.DB, id), ",")))
	}
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

type createUserRequest struct {
	Email       string       `json:"email"`
	Password    string       `json:"password"`
	Role        string       `json:"role"`
	Scopes      *[]userScope `json:"scopes"`
	Permissions []string     `json:"permissions"`
}

func (h *UsersHandler) create(w http.ResponseWriter, r *http.Request) {
	var req createUserRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.Email == "" || req.Password == "" {
		http.Error(w, "email et password requis", http.StatusBadRequest)
		return
	}
	if req.Role == "" {
		req.Role = "user"
	}
	role, ok := normalizePlatformRole(req.Role)
	if !ok || role == "superadmin" {
		writeErr(w, r, http.StatusBadRequest, "api.err.role_admin_user")
		return
	}
	perms, ok := rbac.NormalizePermissions(req.Permissions)
	if !ok {
		writeErr(w, r, http.StatusBadRequest, "api.err.unknown_permission")
		return
	}
	if (role == rbac.RoleDPO || len(perms) > 0) && !h.actorIsSuper(r) {
		writeErr(w, r, http.StatusForbidden, "api.err.superadmin_required")
		return
	}

	hash, err := adminauth.HashPassword(req.Password)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: hash password", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	id := uuid.New().String()
	_, err = h.DB.ExecContext(r.Context(),
		`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		id, req.Email, hash, role,
	)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: create", "err", err)
		}
		writeErr(w, r, http.StatusConflict, "api.err.email_taken")
		return
	}

	if req.Scopes != nil {
		if err := replaceUserScopes(h.DB, id, *req.Scopes); err != nil {
			h.Log.Error("users: create scopes", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
	}
	if err := replaceUserPermissions(h.DB, id, perms); err != nil {
		h.Log.Error("users: create permissions", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "user:"+id, req.Email)
	if role == rbac.RoleDPO || len(perms) > 0 {
		_ = admindb.WriteAudit(h.DB, actor, "set_permissions", "user:"+id,
			fmt.Sprintf("role=%s permissions=%s", role, strings.Join(perms, ",")))
	}
	h.notifyChange()
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(userRow{ID: id, Email: req.Email, Role: role})
}

type changePasswordRequest struct {
	Password string `json:"password"`
}

func (h *UsersHandler) changePassword(w http.ResponseWriter, r *http.Request, id string) {
	var req changePasswordRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if req.Password == "" {
		http.Error(w, "password requis", http.StatusBadRequest)
		return
	}
	if !h.guardProtected(w, r, id) {
		return
	}

	hash, err := adminauth.HashPassword(req.Password)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: hash password", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}

	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET password_hash=? WHERE id=?`, hash, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: changePassword", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "change_password", "user:"+id, "")
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *UsersHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	var role string
	h.DB.QueryRowContext(r.Context(), `SELECT role FROM users WHERE id=?`, id).Scan(&role) //nolint:errcheck
	if role == "superadmin" {
		http.Error(w, "impossible de supprimer le superadmin", http.StatusForbidden)
		return
	}
	if !h.guardProtected(w, r, id) {
		return
	}
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM users WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: delete", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	h.DB.ExecContext(r.Context(), `DELETE FROM user_scopes WHERE user_id=?`, id)     //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM team_members WHERE user_id=?`, id) //nolint:errcheck
	h.DB.ExecContext(r.Context(), `DELETE FROM user_permissions WHERE user_id=?`, id) //nolint:errcheck

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "user:"+id, "")
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}
