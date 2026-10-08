// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/plugins"
)

// maxPluginWasmBytes borne le module installé : le paquet voyage sur le canal de contrôle (4 Mio, base64).
const maxPluginWasmBytes = 2 << 20

// PluginPusher envoie la liste des plugins aux passerelles.
type PluginPusher interface {
	PushPlugins(ctx context.Context)
}

// PluginsHandler gère les plugins WebAssembly installés (ADR 0008). Installer un plugin, c'est faire
// exécuter du code sur les passerelles : réservé aux administrateurs.
type PluginsHandler struct {
	DB     *sql.DB
	Log    *slog.Logger
	Pusher PluginPusher
}

// PluginInfo est la vue d'un plugin installé (sans le module).
type PluginInfo struct {
	plugins.Manifest
	SHA256    string    `json:"sha256"`
	Size      int       `json:"size"`
	UpdatedAt time.Time `json:"updated_at"`
}

type pluginRequest struct {
	Manifest plugins.Manifest `json:"manifest"`
	SHA256   string           `json:"sha256"`
	Wasm     []byte           `json:"wasm"` // base64 en JSON
}

func (h *PluginsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	name := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/plugins"), "/")
	switch {
	case r.Method == http.MethodGet && name == "":
		h.list(w, r)
	case r.Method == http.MethodGet:
		h.get(w, r, name)
	case r.Method == http.MethodPost && name == "":
		h.install(w, r, "")
	case r.Method == http.MethodPut && name != "":
		h.install(w, r, name)
	case r.Method == http.MethodDelete && name != "":
		h.remove(w, r, name)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PluginsHandler) scan(rows interface{ Scan(...any) error }) (PluginInfo, error) {
	var info PluginInfo
	var manifest string
	if err := rows.Scan(&manifest, &info.SHA256, &info.Size, &info.UpdatedAt); err != nil {
		return info, err
	}
	return info, json.Unmarshal([]byte(manifest), &info.Manifest)
}

const pluginCols = `manifest, sha256, length(wasm), updated_at`

func (h *PluginsHandler) list(w http.ResponseWriter, r *http.Request) {
	rows, err := h.DB.QueryContext(r.Context(), `SELECT `+pluginCols+` FROM plugins ORDER BY name`)
	if err != nil {
		if !isCtxErr(err) {
			h.Log.Error("plugins: list", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	defer rows.Close()
	out := make([]PluginInfo, 0)
	for rows.Next() {
		if info, err := h.scan(rows); err == nil {
			out = append(out, info)
		}
	}
	jsonOK(w, out)
}

func (h *PluginsHandler) get(w http.ResponseWriter, r *http.Request, name string) {
	info, err := h.scan(h.DB.QueryRowContext(r.Context(), `SELECT `+pluginCols+` FROM plugins WHERE name=?`, name))
	if err == sql.ErrNoRows {
		http.Error(w, "plugin introuvable", http.StatusNotFound)
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, info)
}

// install crée (POST) ou remplace (PUT) un plugin. Le module est compilé et son contrat vérifié avant
// tout enregistrement : un plugin refusé par une passerelle ne doit pas pouvoir être stocké.
func (h *PluginsHandler) install(w http.ResponseWriter, r *http.Request, name string) {
	var req pluginRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 4<<20)).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if name != "" && req.Manifest.Name != name {
		http.Error(w, "le nom du manifeste doit être celui de l'URL", http.StatusBadRequest)
		return
	}
	if len(req.Wasm) == 0 || len(req.Wasm) > maxPluginWasmBytes {
		http.Error(w, "module .wasm requis (2 Mio au plus)", http.StatusBadRequest)
		return
	}
	sum := sha256.Sum256(req.Wasm)
	got := hex.EncodeToString(sum[:])
	if req.SHA256 == "" || !strings.EqualFold(req.SHA256, got) {
		http.Error(w, "sha256 requis et égal à l'empreinte du module ("+got+")", http.StatusBadRequest)
		return
	}
	p, err := plugins.Load(r.Context(), req.Manifest, req.Wasm, got, h.Log)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	manifest := p.Manifest
	p.Close(r.Context())

	mb, _ := json.Marshal(manifest)
	var exists int
	_ = h.DB.QueryRowContext(r.Context(), `SELECT COUNT(1) FROM plugins WHERE name=?`, manifest.Name).Scan(&exists)
	if name == "" && exists > 0 {
		http.Error(w, "un plugin de ce nom existe déjà (PUT pour le remplacer)", http.StatusConflict)
		return
	}
	if name != "" && exists == 0 {
		http.Error(w, "plugin introuvable", http.StatusNotFound)
		return
	}
	if _, err := h.DB.ExecContext(r.Context(),
		`INSERT INTO plugins (name, manifest, sha256, wasm) VALUES (?, ?, ?, ?)
		 ON CONFLICT(name) DO UPDATE SET manifest=excluded.manifest, sha256=excluded.sha256, wasm=excluded.wasm, updated_at=CURRENT_TIMESTAMP`,
		manifest.Name, string(mb), got, req.Wasm); err != nil {
		if !isCtxErr(err) {
			h.Log.Error("plugins: install", "err", err)
		}
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	action := "create"
	if exists > 0 {
		action = "update"
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), action, "plugin:"+manifest.Name, got)
	h.push()

	status := http.StatusCreated
	if exists > 0 {
		status = http.StatusOK
	}
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(PluginInfo{Manifest: manifest, SHA256: got, Size: len(req.Wasm), UpdatedAt: time.Now().UTC()})
}

func (h *PluginsHandler) remove(w http.ResponseWriter, r *http.Request, name string) {
	res, err := h.DB.ExecContext(r.Context(), `DELETE FROM plugins WHERE name=?`, name)
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if n, _ := res.RowsAffected(); n == 0 {
		http.Error(w, "plugin introuvable", http.StatusNotFound)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "delete", "plugin:"+name, "")
	h.push()
	w.WriteHeader(http.StatusNoContent)
}

func (h *PluginsHandler) push() {
	if h.Pusher != nil {
		go h.Pusher.PushPlugins(context.Background())
	}
}
