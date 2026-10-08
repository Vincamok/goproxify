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
	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/modules"
)

// maskAuthConfig masque les secrets d'une configuration de fournisseur selon le manifeste de son type
// (secrets imbriqués et mots de passe Basic compris). Un type inconnu (ligne ancienne) retombe sur le
// masquage par nom de clé.
func maskAuthConfig(provider string, raw json.RawMessage) json.RawMessage {
	var cfg map[string]any
	if json.Unmarshal(raw, &cfg) != nil || cfg == nil {
		return raw
	}
	if man, ok := middleware.SSOProviderManifest(provider); ok {
		cfg = man.Mask(cfg)
	} else {
		maskKnownSecretKeys(cfg)
	}
	b, err := json.Marshal(cfg)
	if err != nil {
		return raw
	}
	return b
}

var authSecretKeys = map[string]bool{
	"client_secret": true, "session_secret": true, "bind_password": true, "key_pem": true,
	"password": true, "secret": true, "token": true, "api_key": true,
}

func maskKnownSecretKeys(v any) {
	switch t := v.(type) {
	case map[string]any:
		for k, e := range t {
			if s, ok := e.(string); ok && s != "" && authSecretKeys[k] {
				t[k] = modules.Masque
				continue
			}
			maskKnownSecretKeys(e)
		}
	case []any:
		for _, e := range t {
			maskKnownSecretKeys(e)
		}
	}
}

// AuthProviderTypesHandler GET /api/v1/auth-provider-types : manifestes des fournisseurs d'authentification
// (champs imbriqués `oidc.client_secret`, secrets, requis), source de la validation et du masquage.
type AuthProviderTypesHandler struct{}

func (AuthProviderTypesHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		http.NotFound(w, r)
		return
	}
	jsonOK(w, middleware.SSOProviders())
}

// AuthProvider est un fournisseur SSO/Auth partagé entre proxies.
type AuthProvider struct {
	ID        string          `json:"id"`
	Name      string          `json:"name"`
	Provider  string          `json:"provider"` // oidc | github | ldap | ldap_ad | saml | basic | forward | authentik | authelia | ...
	Config    json.RawMessage `json:"config"`
	Enabled   bool            `json:"enabled"`
	CreatedAt time.Time       `json:"created_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

// AuthProvidersHandler gère le CRUD HTTP des fournisseurs SSO.
type AuthProvidersHandler struct {
	DB       *sql.DB
	Log      *slog.Logger
	OnChange func()
}

func (h *AuthProvidersHandler) notifyChange() {
	if h.OnChange != nil {
		go h.OnChange()
	}
}

func (h *AuthProvidersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	path := strings.TrimPrefix(r.URL.Path, "/api/v1/auth-providers")
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
	case r.Method == http.MethodPatch && id != "":
		h.setEnabled(w, r, id)
	case r.Method == http.MethodDelete && id != "":
		h.delete(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *AuthProvidersHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(),
		`SELECT id, name, provider, config, enabled, created_at, updated_at FROM auth_providers ORDER BY name`)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: list", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()

	result := make([]AuthProvider, 0)
	for rows.Next() {
		var ap AuthProvider
		var cfg string
		var enabled int
		if err := rows.Scan(&ap.ID, &ap.Name, &ap.Provider, &cfg, &enabled, &ap.CreatedAt, &ap.UpdatedAt); err != nil {
			continue
		}
		ap.Config = maskAuthConfig(ap.Provider, json.RawMessage(cfg))
		ap.Enabled = enabled == 1
		result = append(result, ap)
	}
	jsonOK(w, result)
}

func (h *AuthProvidersHandler) get(w http.ResponseWriter, r *http.Request, id string) {
	var ap AuthProvider
	var cfg string
	var enabled int
	err := h.DB.QueryRowContext(r.Context(),
		`SELECT id, name, provider, config, enabled, created_at, updated_at FROM auth_providers WHERE id=?`, id,
	).Scan(&ap.ID, &ap.Name, &ap.Provider, &cfg, &enabled, &ap.CreatedAt, &ap.UpdatedAt)
	if err == sql.ErrNoRows {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	ap.Config = maskAuthConfig(ap.Provider, json.RawMessage(cfg))
	ap.Enabled = enabled == 1
	jsonOK(w, ap)
}

type authProviderRequest struct {
	Name     string          `json:"name"`
	Provider string          `json:"provider"`
	Config   json.RawMessage `json:"config"`
	Enabled  *bool           `json:"enabled"`
}

func (h *AuthProvidersHandler) create(w http.ResponseWriter, r *http.Request) {
	var req authProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if req.Name == "" || req.Provider == "" {
		http.Error(w, "name et provider sont requis", http.StatusBadRequest)
		return
	}
	man, ok := middleware.SSOProviderManifest(req.Provider)
	if !ok {
		http.Error(w, "fournisseur inconnu : "+req.Provider, http.StatusBadRequest)
		return
	}
	var newCfg map[string]any
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &newCfg); err != nil {
			http.Error(w, "config invalide : "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if err := man.Validate(newCfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}

	id := uuid.New().String()
	cfg := string(req.Config)
	if cfg == "" {
		cfg = "{}"
	}
	enabled := 1
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}

	_, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO auth_providers (id, name, provider, config, enabled) VALUES (?, ?, ?, ?, ?)`,
		id, req.Name, req.Provider, cfg, enabled,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: create", "err", err) }
		writeErr(w, r, http.StatusConflict, "api.err.name_taken")
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "create", "auth_provider:"+id, req.Name)
	h.notifyChange()

	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	json.NewEncoder(w).Encode(AuthProvider{ //nolint:errcheck
		ID: id, Name: req.Name, Provider: req.Provider,
		Config: maskAuthConfig(req.Provider, req.Config), Enabled: enabled == 1,
	})
}

func (h *AuthProvidersHandler) update(w http.ResponseWriter, r *http.Request, id string) {
	var req authProviderRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}

	// Les secrets absents, vides ou masqués sont repris de la configuration enregistrée ; le type et le
	// nom restent ceux enregistrés quand la requête ne les renseigne pas.
	var oldProvider, oldName, oldCfg string
	switch err := h.DB.QueryRowContext(r.Context(),
		`SELECT provider, name, config FROM auth_providers WHERE id=?`, id).Scan(&oldProvider, &oldName, &oldCfg); {
	case err == sql.ErrNoRows:
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	case err != nil:
		if !isCtxErr(err) {
			h.Log.Error("auth_providers: update lookup", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if req.Provider == "" {
		req.Provider = oldProvider
	}
	if req.Name == "" {
		req.Name = oldName
	}
	man, ok := middleware.SSOProviderManifest(req.Provider)
	if !ok {
		http.Error(w, "fournisseur inconnu : "+req.Provider, http.StatusBadRequest)
		return
	}
	var newCfg map[string]any
	if len(req.Config) > 0 {
		if err := json.Unmarshal(req.Config, &newCfg); err != nil {
			http.Error(w, "config invalide : "+err.Error(), http.StatusBadRequest)
			return
		}
	}
	if req.Provider == oldProvider { // les secrets d'un autre type n'ont pas le même sens
		var old map[string]any
		_ = json.Unmarshal([]byte(oldCfg), &old)
		newCfg = man.KeepSecrets(old, newCfg)
	}
	if err := man.Validate(newCfg); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	cfgBytes, _ := json.Marshal(newCfg)
	cfg := string(cfgBytes)
	enabled := 1
	if req.Enabled != nil && !*req.Enabled {
		enabled = 0
	}

	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE auth_providers SET name=?, provider=?, config=?, enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`,
		req.Name, req.Provider, cfg, enabled, id,
	)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: update", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "update", "auth_provider:"+id, req.Name)
	h.notifyChange()

	w.WriteHeader(http.StatusNoContent)
}

// setEnabled PATCH /api/v1/auth-providers/:id {"enabled": bool} : active ou désactive sans toucher à la config.
func (h *AuthProvidersHandler) setEnabled(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Enabled *bool `json:"enabled"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Enabled == nil {
		http.Error(w, "enabled (booléen) requis", http.StatusBadRequest)
		return
	}
	v := 0
	if *req.Enabled {
		v = 1
	}
	res, err := h.DB.ExecContext(r.Context(),
		`UPDATE auth_providers SET enabled=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, v, id)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("auth_providers: set enabled", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}
	action := "disable"
	if v == 1 {
		action = "enable"
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), action, "auth_provider:"+id, "")
	h.notifyChange()
	w.WriteHeader(http.StatusNoContent)
}

func (h *AuthProvidersHandler) delete(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM auth_providers WHERE id=?`, id)
	if err != nil {
		if !isCtxErr(err) { h.Log.Error("auth_providers: delete", "err", err) }
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	n, _ := res.RowsAffected()
	if n == 0 {
		http.Error(w, "provider introuvable", http.StatusNotFound)
		return
	}

	actor := adminauth.UserIDFromContext(r.Context())
	_ = admindb.WriteAudit(h.DB, actor, "delete", "auth_provider:"+id, "")
	h.notifyChange()

	w.WriteHeader(http.StatusNoContent)
}
