// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// ArchitectureHandler expose architecture.json (référentiel de la topologie), son historique et sa restauration.
//
//	GET  /api/v1/architecture
//	GET  /api/v1/architecture/versions
//	GET  /api/v1/architecture/versions/{name}
//	POST /api/v1/architecture/restore   {"name": "architecture-….json"}
type ArchitectureHandler struct {
	DB    *sql.DB
	Log   *slog.Logger
	Store *archstore.Store // nil = persistance disque désactivée
	// OnRestore est appelé après une restauration réussie (réalignement de la base, reconnexion des passerelles).
	OnRestore func()
}

func (h *ArchitectureHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if h.Store == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/architecture"), "/")
	switch {
	case r.Method == http.MethodGet && sub == "":
		h.get(w, r)
	case r.Method == http.MethodGet && strings.HasPrefix(sub, "versions/"):
		h.version(w, r, strings.TrimPrefix(sub, "versions/"))
	case r.Method == http.MethodGet && sub == "groups":
		h.groups(w, r)
	case r.Method == http.MethodGet && sub == "versions":
		h.versions(w, r)
	case r.Method == http.MethodPost && sub == "restore":
		h.restore(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *ArchitectureHandler) get(w http.ResponseWriter, r *http.Request) {
	arch, err := h.Store.Get()
	if err != nil {
		h.Log.Error("architecture: lecture", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, arch)
}

func (h *ArchitectureHandler) version(w http.ResponseWriter, r *http.Request, name string) {
	arch, err := h.Store.Version(name)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	jsonOK(w, arch)
}

func (h *ArchitectureHandler) versions(w http.ResponseWriter, r *http.Request) {
	list, err := h.Store.Versions()
	if err != nil {
		h.Log.Error("architecture: versions", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if list == nil {
		list = []archstore.VersionInfo{}
	}
	jsonOK(w, list)
}

func (h *ArchitectureHandler) restore(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Name string `json:"name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil || req.Name == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	if err := h.Store.Restore(req.Name); err != nil {
		h.Log.Warn("architecture: restore", "version", req.Name, "err", err)
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	rep, err := h.Store.ApplyToDB(r.Context(), h.DB)
	if err != nil {
		h.Log.Warn("architecture: réalignement après restauration", "err", err)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "restore", "architecture", req.Name)
	if h.OnRestore != nil {
		h.OnRestore()
	}
	jsonOK(w, map[string]any{"restored": req.Name, "applied": rep})
}

// groups retourne les groupes HA déclarés dans architecture.json : nom → membres (id, nom).
// Lecture seule, sans secret : l'UI s'en sert pour indiquer qu'un réglage s'applique au groupe.
func (h *ArchitectureHandler) groups(w http.ResponseWriter, r *http.Request) {
	type member struct {
		ID   string `json:"id"`
		Name string `json:"name"`
	}
	names, members := h.Store.Groups()
	out := make(map[string][]member, len(names))
	for _, g := range names {
		list := make([]member, 0, len(members[g]))
		for _, n := range members[g] {
			list = append(list, member{ID: n.ID, Name: n.Name})
		}
		out[g] = list
	}
	jsonOK(w, out)
}
