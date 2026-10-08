// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log/slog"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/middleware"
)

// Snippet est un profil réutilisable (IP, TLS, rate-limit, CORS, headers...).
// Il est référencé par son nom dans la config d'un proxy.
type Snippet struct {
	ID          string          `json:"id"`
	Name        string          `json:"name"`
	Type        string          `json:"type"` // ip_filter | rate_limit | cors | headers | tls | geo_ip | bot | waf
	Description string          `json:"description"`
	Config      json.RawMessage `json:"config"` // JSON libre selon le type
	CreatedAt   time.Time       `json:"created_at"`
	UpdatedAt   time.Time       `json:"updated_at"`
}

// SnippetsHandler gère le CRUD HTTP des snippets.
type SnippetsHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	OnChange func()
}

func (h *SnippetsHandler) notifyChange() {
	if h.OnChange != nil {
		go h.OnChange()
	}
}

func (h *SnippetsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/snippets")
	path = strings.TrimPrefix(path, "/")
	id := strings.Split(path, "/")[0]

	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodGet && id != "":
		h.get(w, r, id)
	case r.Method == http.MethodPost && id == "":
		h.create(w, r)
	case r.Method == http.MethodPut && id != "":
		h.update(w, r, id)
	case r.Method == http.MethodDelete && id != "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *SnippetsHandler) list(w http.ResponseWriter, r *http.Request) {
	typeFilter := r.URL.Query().Get("type")
	var (
		rows *sql.Rows
		err  error
	)
	if typeFilter != "" {
		rows, err = h.DB.QueryContext(r.Context(),
			`SELECT id, name, type, description, config, created_at, updated_at FROM snippets WHERE type=? ORDER BY name`,
			typeFilter)
	} else {
		rows, err = h.DB.QueryContext(r.Context(),
			`SELECT id, name, type, description, config, created_at, updated_at FROM snippets ORDER BY name`)
	}
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("snippets: list", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]Snippet, 0)
	for rows.Next() {
		var s Snippet
		var cfg string
		if err := rows.Scan(&s.ID, &s.Name, &s.Type, &s.Description, &cfg, &s.CreatedAt, &s.UpdatedAt); err != nil {
			continue
		}
		s.Config = maskSnippetConfig(s.Type, json.RawMessage(cfg))
		result = append(result, s)
	}
	jsonOK(w, result)
}

func (h *SnippetsHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var s Snippet
	var cfg string
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, type, description, config, created_at, updated_at FROM snippets WHERE id=?`, id,
	).Scan(&s.ID, &s.Name, &s.Type, &s.Description, &cfg, &s.CreatedAt, &s.UpdatedAt)
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	s.Config = maskSnippetConfig(s.Type, json.RawMessage(cfg))
	jsonOK(w, s)
}

type snippetRequest struct {
	Name        string          `json:"name"`
	Type        string          `json:"type"`
	Description *string         `json:"description"` // nil = inchangé à la mise à jour
	Config      json.RawMessage `json:"config"`
}

var validSnippetTypes = map[string]bool{
	"ip_filter": true, "rate_limit": true, "cors": true,
	"headers": true, "tls": true, "geo_ip": true, "bot": true, "waf": true,
}

func (h *SnippetsHandler) create(w http.ResponseWriter, r *http.Request) {
	var req snippetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.Name == "" || !validSnippetTypes[req.Type] {
		http.Error(w, "name requis et type doit être : ip_filter | rate_limit | cors | headers | tls | geo_ip | bot | waf", http.StatusBadRequest)
		return
	}

	if err := validateSnippetConfig(req.Type, req.Config, nil); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	desc := ""
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO snippets (id, name, type, description, config) VALUES (?, ?, ?, ?, ?)`,
		id, req.Name, req.Type, desc, cfg,
	)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("snippets: create", "err", err)
		}
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "snippet:"+id, req.Name)
	h.notifyChange()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(Snippet{ID: id, Name: req.Name, Type: req.Type, Description: desc, Config: maskSnippetConfig(req.Type, req.Config)}) //nolint:errcheck
}

func (h *SnippetsHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req snippetRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}

	var oldType, oldCfg string
	switch err := h.DB.QueryRowContext(r.Context(), `SELECT type, config FROM snippets WHERE id=?`, id).Scan(&oldType, &oldCfg); {
	case err == sql.ErrNoRows:
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	case err != nil:
		if !isCtxErr(err) {
			h.Log.Error("snippets: update lookup", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if req.Type == "" {
		req.Type = oldType
	}
	if !validSnippetTypes[req.Type] {
		http.Error(w, "type doit être : ip_filter | rate_limit | cors | headers | tls | geo_ip | bot | waf", http.StatusBadRequest)
		return
	}
	var prev json.RawMessage
	if req.Type == oldType { // les secrets d'un autre type n'ont pas le même sens
		prev = json.RawMessage(oldCfg)
	}
	if err := validateSnippetConfig(req.Type, req.Config, prev); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if merged, ok := keepSnippetSecrets(req.Type, prev, req.Config); ok {
		req.Config = merged
	}
	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	var desc any
	if req.Description != nil {
		desc = strings.TrimSpace(*req.Description)
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE snippets SET name=?, type=?, description=COALESCE(?, description), config=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		req.Name, req.Type, desc, cfg, id,
	)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("snippets: update", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "snippet:"+id, req.Name)
	h.notifyChange()

	w.WriteHeader(http.StatusNoContent)
}

func (h *SnippetsHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM snippets WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("snippets: delete", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		writeErr(w, r, http.StatusNotFound, "api.err.snippet_not_found")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "snippet:"+id, "")
	h.notifyChange()

	w.WriteHeader(http.StatusNoContent)
}

// isDetectorSnippet indique si le type de snippet est un détecteur du registre (ADR 0007).
func isDetectorSnippet(typ string) bool {
	_, ok := middleware.DetectorManifest(typ)
	return ok
}

func decodeSnippetConfig(raw json.RawMessage) (map[string]any, error) {
	var cfg map[string]any
	if len(raw) == 0 {
		return cfg, nil
	}
	if err := json.Unmarshal(raw, &cfg); err != nil {
		return nil, err
	}
	return cfg, nil
}

// validateSnippetConfig valide la configuration d'un snippet de détecteur (clés, champs requis,
// valeurs). Les autres types gardent une configuration libre. prev, la configuration enregistrée,
// permet à un secret masqué de ne pas compter comme une valeur à valider.
func validateSnippetConfig(typ string, raw, prev json.RawMessage) error {
	if !isDetectorSnippet(typ) {
		return nil
	}
	cfg, err := decodeSnippetConfig(raw)
	if err != nil {
		return fmt.Errorf("config invalide : %w", err)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	if merged, ok := keepSnippetSecrets(typ, prev, raw); ok {
		cfg, _ = decodeSnippetConfig(merged)
	}
	return middleware.ValidateDetector(typ, cfg)
}

// keepSnippetSecrets reprend de la configuration enregistrée les secrets que la nouvelle omet ou
// renvoie masqués.
func keepSnippetSecrets(typ string, prev, next json.RawMessage) (json.RawMessage, bool) {
	man, ok := middleware.DetectorManifest(typ)
	if !ok || len(prev) == 0 {
		return nil, false
	}
	oldCfg, err1 := decodeSnippetConfig(prev)
	newCfg, err2 := decodeSnippetConfig(next)
	if err1 != nil || err2 != nil {
		return nil, false
	}
	if newCfg == nil {
		newCfg = map[string]any{}
	}
	b, err := json.Marshal(man.KeepSecrets(oldCfg, newCfg))
	return b, err == nil
}

// maskSnippetConfig masque les secrets d'un snippet de détecteur (secret du défi bot, clé du captcha).
func maskSnippetConfig(typ string, raw json.RawMessage) json.RawMessage {
	man, ok := middleware.DetectorManifest(typ)
	if !ok {
		return raw
	}
	cfg, err := decodeSnippetConfig(raw)
	if err != nil || cfg == nil {
		return raw
	}
	b, err := json.Marshal(man.Mask(cfg))
	if err != nil {
		return raw
	}
	return b
}

// DetectorTypesHandler GET /api/v1/detector-types : manifestes des détecteurs par route (ip_filter,
// geo_ip, bot, waf), source de la validation des snippets.
type DetectorTypesHandler struct{}

func (DetectorTypesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, middleware.Detectors())
}
