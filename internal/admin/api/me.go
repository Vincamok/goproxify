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

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mfa"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// MeHandler gère /api/v1/me — profil de l'utilisateur connecté.
type MeHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	OnChange func() // appelé après changement email/mot de passe

	// JWTSecret sert à rendre une session neuve après un changement de mot de passe (les autres sont révoquées).
	JWTSecret string
}

func (h *MeHandler) notifyChange() {
	if h.OnChange != nil {
		go h.OnChange()
	}
}

type meTeam struct {
	TeamID   string            `json:"team_id"`
	TeamName string            `json:"team_name"`
	Accesses []rbac.TeamAccess `json:"accesses"`
}

type meResponse struct {
	ID              string     `json:"id"`
	Email           string     `json:"email"`
	Role            string     `json:"role"` // "superadmin" | "admin" | "user"
	IsSuper         bool       `json:"is_super"`
	CreatedAt       *time.Time `json:"created_at,omitempty"`
	Teams           []meTeam   `json:"teams"`
	// Permissions du catalogue que portent les accès de ses équipes (vide pour un administrateur, qui les détient toutes).
	Granted []string `json:"granted"`
	// Capacités effectives (rôle superadmin, équipes), ex. ["gdpr:reveal"].
	Permissions []string `json:"permissions"`
}

func (h *MeHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	userID := adminauth.UserIDFromContext(r.Context())
	if userID == "" {
		writeErr(w, r, http.StatusUnauthorized, "api.err.unauth")
		return
	}

	path := strings.TrimPrefix(r.URL.Path, "/api/v1/me")
	path = strings.TrimPrefix(path, "/")

	switch {
	case r.Method == http.MethodGet && path == "":
		h.getMe(w, r, userID)
	case r.Method == http.MethodPatch && path == "":
		h.updateEmail(w, r, userID)
	case r.Method == http.MethodPost && path == "change-password":
		h.changePassword(w, r, userID)
	case path == "tokens" || strings.HasPrefix(path, "tokens/"):
		// Fallback si le mux envoie /me/tokens vers MeHandler.
		(&UserTokensHandler{DB: h.DB, Log: h.Log}).ServeHTTP(w, r)
	default:
		http.Error(w, "route inconnue", http.StatusNotFound)
	}
}

// GetMeHTTP est un http.HandlerFunc compatible pour GET /api/v1/auth/me.
func (h *MeHandler) GetMeHTTP(w http.ResponseWriter, r *http.Request) {
	userID := adminauth.UserIDFromContext(r.Context())
	if userID == "" {
		writeErr(w, r, http.StatusUnauthorized, "api.err.unauth")
		return
	}
	h.getMe(w, r, userID)
}

func (h *MeHandler) getMe(w http.ResponseWriter, r *http.Request, userID string) {
	var me meResponse
	var createdAt sql.NullTime
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, email, role, created_at FROM users WHERE id=?`, userID,
	).Scan(&me.ID, &me.Email, &me.Role, &createdAt)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	if createdAt.Valid {
		me.CreatedAt = &createdAt.Time
	}
	me.IsSuper = me.Role == "superadmin"
	access, err := rbac.EffectiveAccess(r.Context(), h.DB, userID)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	me.Permissions = []string{}
	for _, p := range access.Permissions {
		me.Permissions = append(me.Permissions, p.Permission)
	}
	// Équipes avec leurs accès. Un administrateur voit toute la plateforme : ses équipes ne lui apportent pas d'accès
	// sur les ressources, donc aucun accès effectif n'est renvoyé (le navigateur y lit « accès global »).
	me.Teams = []meTeam{}
	for _, t := range access.Teams {
		me.Teams = append(me.Teams, meTeam{TeamID: t.ID, TeamName: t.Name, Accesses: t.Accesses})
	}
	me.Granted = access.Granted

	jsonOK(w, me)
}

func (h *MeHandler) updateEmail(w http.ResponseWriter, r *http.Request, userID string) {
	var req struct {
		Email string `json:"email"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || strings.TrimSpace(req.Email) == "" {
		http.Error(w, "email invalide", http.StatusBadRequest)
		return
	}
	_, err := h.DB.ExecContext(r.Context(),
		`UPDATE users SET email=? WHERE id=?`, strings.TrimSpace(req.Email), userID)
	if err != nil {
		writeErr(w, r, http.StatusConflict, "api.err.email_taken")
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "update_email", "user:"+userID, req.Email)
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

type changePwReq struct {
	CurrentPassword string `json:"current_password"`
	NewPassword     string `json:"new_password"`
}

func (h *MeHandler) changePassword(w http.ResponseWriter, r *http.Request, userID string) {
	var req changePwReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.CurrentPassword == "" || req.NewPassword == "" {
		http.Error(w, "champs requis", http.StatusBadRequest)
		return
	}

	var hash string
	if err := h.DB.QueryRowContext(r.Context(),
		`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.user_not_found")
		return
	}
	if !adminauth.CheckPassword(hash, req.CurrentPassword) {
		http.Error(w, "mot de passe actuel incorrect", http.StatusUnauthorized)
		return
	}

	newHash, err := adminauth.HashPassword(req.NewPassword)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if _, err := h.DB.ExecContext(r.Context(), `UPDATE users SET password_hash=? WHERE id=?`, newHash, userID); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	// Toute session émise avant ce changement est révoquée (une session volée ne survit pas au nouveau mot de passe) ;
	// l'appelant en reçoit une neuve pour ne pas être déconnecté. Les appareils de confiance aussi : sinon le mot de
	// passe seul suffirait encore depuis un appareil gardé par celui qu'on veut exclure.
	_ = adminauth.RevokeSessions(r.Context(), h.DB, userID)
	_ = mfa.NewStore(h.DB).DeleteTrustedDevices(r.Context(), userID)
	_ = admindb.WriteAudit(h.DB, userID, "change_password", "user:"+userID, "")
	h.notifyChange()
	if adminauth.AuthKindFromContext(r.Context()) == adminauth.AuthKindJWT && h.JWTSecret != "" {
		if tok, err := adminauth.SignJWT(userID, h.JWTSecret, 24*time.Hour); err == nil {
			jsonOK(w, map[string]string{"token": tok})
			return
		}
	}
	w.WriteHeader(http.StatusNoContent)
}
