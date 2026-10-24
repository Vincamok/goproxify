// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// ArchitectureHandler expose architecture.json (référentiel de la topologie), son historique et sa restauration.
//
//	GET  /api/v1/architecture
//	GET  /api/v1/architecture/versions
//	GET  /api/v1/architecture/versions/{name}
//	POST /api/v1/architecture/restore   {"name": "architecture-….json"}
//	POST /api/v1/architecture/recover   {"edges": ["nom", …]}  (facultatif : toutes les passerelles connues)
type ArchitectureHandler struct {
	DB    *sql.DB
	Log   *slog.Logger
	Store *archstore.Store // nil = persistance disque désactivée
	// OnRestore est appelé après une restauration réussie (réalignement de la base, reconnexion des passerelles).
	OnRestore func()
	// FetchCards demande leur fiche de groupe aux passerelles désignées (toutes si la liste est vide). Rend les fiches
	// reçues et, pour les autres, la raison de l'absence.
	FetchCards func(ctx context.Context, edges []string) (cards []edgews.GroupCard, unreachable []string)
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
	case r.Method == http.MethodPost && sub == "recover":
		h.recover(w, r)
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

// recover reconstitue architecture.json à partir des fiches que détiennent les passerelles (ADR 0014, section 8) : un
// Admin neuf, connecté à au moins une passerelle, retrouve les groupes, leurs membres et leurs domaines. Ce que le
// fichier connaît déjà n'est pas modifié.
func (h *ArchitectureHandler) recover(w http.ResponseWriter, r *http.Request) {
	if h.FetchCards == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	var req struct {
		Edges []string `json:"edges"`
	}
	if r.Body != nil {
		_ = json.NewDecoder(r.Body).Decode(&req) // corps facultatif
	}
	cards, unreachable := h.FetchCards(r.Context(), req.Edges)
	h.relinkDomains(r.Context(), cards)
	rep, err := h.Store.MergeCards(cards)
	if err != nil {
		h.Log.Error("architecture: reconstitution", "err", err)
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	applied, err := h.Store.ApplyToDB(r.Context(), h.DB)
	if err != nil {
		h.Log.Warn("architecture: réalignement après reconstitution", "err", err)
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "recover", "architecture", strings.Join(rep.Groups, ","))
	if h.OnRestore != nil && (rep.Nodes > 0 || rep.Domains > 0) {
		h.OnRestore()
	}
	h.Log.Info("architecture: reconstituée à partir des fiches de groupe", "fiches", len(cards), "groupes", rep.Groups, "noeuds", rep.Nodes, "domaines", rep.Domains)
	jsonOK(w, map[string]any{"cards": len(cards), "unreachable": unreachable, "added": rep, "applied": applied})
}

// relinkDomains remplace, dans les domaines des fiches, les jetons de l'ancien Admin par ceux que l'Admin neuf a créés pour les passerelles
// retrouvées par leur nom. Un nom sans jeton actif laisse le domaine tel quel.
func (h *ArchitectureHandler) relinkDomains(ctx context.Context, cards []edgews.GroupCard) {
	lookup := func(name string) string {
		var id string
		if h.DB == nil || name == "" {
			return ""
		}
		_ = h.DB.QueryRowContext(ctx, `SELECT id FROM tokens WHERE role='edge' AND revoked=0 AND node_name=? ORDER BY created_at DESC LIMIT 1`, name).Scan(&id)
		return id
	}
	for ci := range cards {
		for di := range cards[ci].Domains {
			d := &cards[ci].Domains[di]
			if !strings.HasPrefix(d.EdgeID, haEntryPrefix) {
				if id := lookup(d.EdgeName); id != "" {
					d.EdgeID = id
				}
			}
			if id := lookup(d.DelegatedToName); id != "" {
				d.DelegatedToEdgeID = id
			}
		}
	}
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
