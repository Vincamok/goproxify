// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/admin/audit"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/backup"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

func (h *BackupHandler) keyAudit(r *http.Request, action string, sev audit.Severity, detail string) {
	if h.Auditor == nil {
		return
	}
	uid := adminauth.UserIDFromContext(r.Context())
	actor := uid
	if h.DB != nil {
		var email string
		if h.DB.QueryRow(`SELECT email FROM users WHERE id=?`, uid).Scan(&email) == nil {
			actor = email
		}
	}
	h.Auditor.Log(r.Context(), audit.Event{
		Action: action, Actor: actor, UserID: uid, IP: audit.IPFrom(r),
		ResourceType: "backup_key", ResourceID: "backup", Detail: detail, Severity: sev,
	})
}

// requireKeySuperadmin : la clé de chiffrement des sauvegardes protège tous les secrets de l'instance.
func (h *BackupHandler) requireKeySuperadmin(w http.ResponseWriter, r *http.Request) bool {
	if h.Keys == nil {
		http.Error(w, "stockage de la clé indisponible (storage.base_path non défini)", http.StatusServiceUnavailable)
		return false
	}
	if !rbac.IsSuperAdmin(r.Context(), h.DB, adminauth.UserIDFromContext(r.Context())) {
		http.Error(w, "réservé au superadmin", http.StatusForbidden)
		return false
	}
	return true
}

func (h *BackupHandler) keyStatus(w http.ResponseWriter, r *http.Request) {
	if h.Keys == nil {
		jsonOK(w, backup.KeyStatus{Source: "none"})
		return
	}
	jsonOK(w, h.Keys.Status())
}

// setKey : {"action":"generate"} génère une clé (renvoyée cette seule fois) ; {"key":"…"} en fixe une.
func (h *BackupHandler) setKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireKeySuperadmin(w, r) {
		return
	}
	var body struct {
		Action string `json:"action"`
		Key    string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	key := body.Key
	if body.Action == "generate" {
		var err error
		if key, err = backup.GenerateKey(); err != nil {
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}
	rotated, err := h.Keys.Set(key)
	if err != nil {
		code := http.StatusBadRequest
		if errors.Is(err, backup.ErrKeyFromEnv) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	h.keyAudit(r, "backup_key_set", audit.Critical, "empreinte "+backup.Fingerprint(key))
	resp := map[string]any{"fingerprint": backup.Fingerprint(key), "rotated": rotated}
	if body.Action == "generate" {
		resp["key"] = key // affichée une seule fois
	}
	jsonOK(w, resp)
}

func (h *BackupHandler) deleteKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireKeySuperadmin(w, r) {
		return
	}
	if err := h.Keys.Deactivate(); err != nil {
		code := http.StatusInternalServerError
		if errors.Is(err, backup.ErrKeyFromEnv) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	h.keyAudit(r, "backup_key_deactivate", audit.Critical, "")
	w.WriteHeader(http.StatusNoContent)
}

// revealKey exige le mot de passe du superadmin : une session volée ne suffit pas à lire la clé.
func (h *BackupHandler) revealKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireKeySuperadmin(w, r) {
		return
	}
	var body struct {
		Password    string `json:"password"`
		Fingerprint string `json:"fingerprint"` // vide = clé active ; sinon une clé retirée
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<12)).Decode(&body); err != nil || body.Password == "" {
		http.Error(w, "mot de passe requis", http.StatusBadRequest)
		return
	}
	if !h.passwordMatches(adminauth.UserIDFromContext(r.Context()), body.Password) {
		time.Sleep(time.Second) // freine les essais en rafale
		h.keyAudit(r, "backup_key_reveal_denied", audit.Critical, "mot de passe incorrect")
		http.Error(w, "mot de passe incorrect", http.StatusForbidden)
		return
	}
	key, err := h.Keys.Reveal(body.Fingerprint)
	if err != nil {
		code := http.StatusNotFound
		if errors.Is(err, backup.ErrKeyFromEnv) {
			code = http.StatusConflict
		}
		http.Error(w, err.Error(), code)
		return
	}
	h.keyAudit(r, "backup_key_reveal", audit.Critical, "empreinte "+backup.Fingerprint(key))
	w.Header().Set("Cache-Control", "no-store")
	jsonOK(w, map[string]string{"key": key, "fingerprint": backup.Fingerprint(key)})
}

func (h *BackupHandler) passwordMatches(userID, password string) bool {
	var hash string
	if err := h.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, userID).Scan(&hash); err != nil && !errors.Is(err, sql.ErrNoRows) {
		return false
	}
	return hash != "" && adminauth.CheckPassword(hash, password)
}

// addRetiredKey : {"key":"…"} ajoute une ancienne clé (par exemple l'ancienne GPX_BACKUP_KEY) pour
// relire les snapshots qu'elle avait chiffrés.
func (h *BackupHandler) addRetiredKey(w http.ResponseWriter, r *http.Request) {
	if !h.requireKeySuperadmin(w, r) {
		return
	}
	var body struct {
		Key string `json:"key"`
	}
	if err := json.NewDecoder(io.LimitReader(r.Body, 1<<14)).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if err := h.Keys.AddRetired(body.Key); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	h.keyAudit(r, "backup_key_add_retired", audit.Critical, "empreinte "+backup.Fingerprint(body.Key))
	jsonOK(w, map[string]string{"fingerprint": backup.Fingerprint(body.Key)})
}

// forgetRetiredKey oublie une clé retirée : les snapshots qu'elle a chiffrés deviennent illisibles.
func (h *BackupHandler) forgetRetiredKey(w http.ResponseWriter, r *http.Request, fingerprint string) {
	if !h.requireKeySuperadmin(w, r) {
		return
	}
	if err := h.Keys.ForgetRetired(fingerprint); err != nil {
		http.Error(w, err.Error(), http.StatusNotFound)
		return
	}
	h.keyAudit(r, "backup_key_forget_retired", audit.Critical, "empreinte "+fingerprint)
	w.WriteHeader(http.StatusNoContent)
}
