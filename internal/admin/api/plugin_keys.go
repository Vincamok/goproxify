// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/ed25519"
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/plugins"
)

// PluginKeysHandler gère les clés publiques de confiance pour la signature des plugins (ADR 0008).
// Tant qu'aucune clé n'est enregistrée, la signature est facultative ; dès qu'il y en a une, tout
// plugin installé ou remplacé doit être signé par l'une d'elles.
type PluginKeysHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

// PluginKey est une clé de confiance.
type PluginKey struct {
	ID        string    `json:"id"`
	Name      string    `json:"name"`
	PublicKey string    `json:"public_key"`
	CreatedAt time.Time `json:"created_at"`
}

func (h *PluginKeysHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	id := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/plugin-keys"), "/")
	switch {
	case r.Method == http.MethodGet && id == "":
		h.list(w, r)
	case r.Method == http.MethodPost && id == "":
		h.add(w, r)
	case r.Method == http.MethodDelete && id != "":
		h.remove(w, r, id)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PluginKeysHandler) list(w http.ResponseWriter, r *http.Request) {
	keys, err := loadPluginKeys(r.Context(), h.DB)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, keys)
}

func (h *PluginKeysHandler) add(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name      string `json:"name"`
		PublicKey string `json:"public_key"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	pub, err := plugins.ParsePublicKey(strings.TrimSpace(req.PublicKey))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	name := strings.TrimSpace(req.Name)
	if name == "" {
		http.Error(w, "name requis", http.StatusBadRequest)
		return
	}
	id := plugins.KeyID(pub)
	b64 := base64.StdEncoding.EncodeToString(pub)
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO plugin_trusted_keys (id, name, public_key) VALUES (?, ?, ?)`, id, name, b64); err != nil {
		http.Error(w, "cette clé est déjà enregistrée", http.StatusConflict)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "create", "plugin_key:"+id, name)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(PluginKey{ID: id, Name: name, PublicKey: b64, CreatedAt: time.Now().UTC()})
}

func (h *PluginKeysHandler) remove(w http.ResponseWriter, r *http.Request, id string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM plugin_trusted_keys WHERE id=?`, id)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "clé introuvable", http.StatusNotFound)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "delete", "plugin_key:"+id, "")
	w.WriteHeader(http.StatusNoContent)
}

func loadPluginKeys(ctx context.Context, db *sql.DB) ([]PluginKey, error) {
	rows, err := db.QueryContext(ctx, `SELECT id, name, public_key, created_at FROM plugin_trusted_keys ORDER BY name`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []PluginKey{}
	for rows.Next() {
		var k PluginKey
		if err := rows.Scan(&k.ID, &k.Name, &k.PublicKey, &k.CreatedAt); err == nil {
			out = append(out, k)
		}
	}
	return out, rows.Err()
}

// verifyPluginSignature applique la politique de signature : avec des clés de confiance, la signature
// est obligatoire et doit être celle d'une de ces clés ; sans clé, elle est facultative mais, si elle est
// fournie, elle doit se vérifier (une signature qu'on ne peut pas contrôler ne compte pas). Retourne
// l'identifiant de la clé signataire ("" pour un paquet non signé).
func verifyPluginSignature(ctx context.Context, db *sql.DB, m plugins.Manifest, wasmSHA, signature string) (string, string) {
	keys, err := loadPluginKeys(ctx, db)
	if err != nil {
		return "", "clés de confiance illisibles"
	}
	if signature == "" {
		if len(keys) > 0 {
			return "", "signature requise : des clés de confiance sont configurées"
		}
		return "", ""
	}
	if len(keys) == 0 {
		return "", "signature fournie mais aucune clé de confiance n'est enregistrée (POST /api/v1/plugin-keys)"
	}
	for _, k := range keys {
		pub, err := plugins.ParsePublicKey(k.PublicKey)
		if err != nil {
			continue
		}
		if plugins.Verify(ed25519.PublicKey(pub), m, wasmSHA, signature) {
			return k.ID, ""
		}
	}
	return "", "signature invalide ou clé non approuvée"
}
