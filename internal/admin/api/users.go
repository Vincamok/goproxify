// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mfa"
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
	case r.Method == http.MethodGet && id != "" && sub == "access":
		h.access(w, r, id)
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
	// EffectivePermissions : capacités du compte, par le rôle superadmin ou par ses équipes.
	EffectivePermissions []string `json:"effective_permissions"`
}

type userTeam struct {
	TeamID string `json:"team_id"`
}

type userDetail struct {
	ID                   string     `json:"id"`
	Email                string     `json:"email"`
	Role                 string     `json:"role"`
	CreatedAt            time.Time  `json:"created_at"`
	Teams                []userTeam `json:"teams"`
	EffectivePermissions []string   `json:"effective_permissions"`
}

// orEmpty évite un null JSON pour une liste vide.
func orEmpty(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
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

	jsonOK(w, userDetail{ID: u.ID, Email: u.Email, Role: u.Role, CreatedAt: u.CreatedAt, Teams: teams,
		EffectivePermissions: orEmpty(rbac.UserPermissions(r.Context(), h.DB, id)),
	})
}

// access : GET /api/v1/users/{id}/access. Ce que le compte peut faire et d'où lui vient chaque droit : son rôle, ses
// équipes, les accès et les capacités qu'elles apportent. C'est la seule définition ; la fiche du compte l'affiche.
func (h *UsersHandler) access(w http.ResponseWriter, r *http.Request, id string) {
	if rbac.UserRole(r.Context(), h.DB, id) == "" {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	out, err := rbac.EffectiveAccess(r.Context(), h.DB, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("users: access", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, out)
}

func normalizePlatformRole(role string) (string, bool) {
	switch role {
	case "admin", "user":
		return role, true
	case "operator", "viewer":
		return "user", true // compat douce
	case "superadmin":
		return "superadmin", false // non assignable via API
	default:
		return "", false
	}
}

type updateUserRequest struct {
	Email       string       `json:"email"`
	Role        string       `json:"role"`
	Password    string       `json:"password"`
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
			_ = adminauth.RevokeSessions(r.Context(), h.DB, id)
			_ = mfa.NewStore(h.DB).DeleteTrustedDevices(r.Context(), id)
		}
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "user:"+id, req.Email)
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

type createUserRequest struct {
	Email       string       `json:"email"`
	Password    string       `json:"password"`
	Role        string       `json:"role"`
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

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "user:"+id, req.Email)
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
		`UPDATE users SET password_hash=?, tokens_valid_after=? WHERE id=?`, hash, time.Now().Unix(), id)
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
	// Un mot de passe réinitialisé par un admin ne laisse aucun appareil dispensé du second facteur.
	_ = mfa.NewStore(h.DB).DeleteTrustedDevices(r.Context(), id)

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
	h.DB.ExecContext(r.Context(), `DELETE FROM team_members WHERE user_id=?`, id) //nolint:errcheck
	// Ce qui authentifie ou rétablit l'accès du compte ne lui survit pas : jetons API, méthodes MFA, codes de secours,
	// appareils de confiance, défis en cours.
	for _, q := range []string{
		`DELETE FROM user_api_token_scopes WHERE token_id IN (SELECT id FROM user_api_tokens WHERE user_id=?)`,
		`DELETE FROM user_api_tokens WHERE user_id=?`,
		`DELETE FROM user_mfa WHERE user_id=?`,
		`DELETE FROM user_mfa_challenges WHERE user_id=?`,
		`DELETE FROM user_backup_codes WHERE user_id=?`,
		`DELETE FROM user_trusted_devices WHERE user_id=?`,
	} {
		h.DB.ExecContext(r.Context(), q, id) //nolint:errcheck
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "user:"+id, "")
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}
