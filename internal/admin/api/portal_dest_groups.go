// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

const destGroupsPath = "/api/v1/portal/destination-groups"

// PortalDestGroup est un groupe de destinations (machines SSH / conteneurs) du catalogue, propre à une
// passerelle (ou à son groupe HA). Une entrée du portail qui l'utilise offre toutes ses destinations.
type PortalDestGroup struct {
	ID          string   `json:"id"`
	EdgeName    string   `json:"edge_name"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Targets     []string `json:"targets"` // identifiants de destinations du catalogue
}

const destGroupCols = `id, edge_name, name, description, targets_json`

func (h *PortalHandler) handleDestGroups(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, destGroupsPath), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.listDestGroups(w, r)
	case rest == "" && r.Method == http.MethodPost:
		h.saveDestGroup(w, r, "")
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodGet:
		h.getDestGroup(w, r, rest)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodPut:
		h.saveDestGroup(w, r, rest)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodDelete:
		h.deleteDestGroup(w, r, rest)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func scanDestGroup(row scannable) (PortalDestGroup, error) {
	var g PortalDestGroup
	var targets string
	if err := row.Scan(&g.ID, &g.EdgeName, &g.Name, &g.Description, &targets); err != nil {
		return g, err
	}
	_ = json.Unmarshal([]byte(targets), &g.Targets)
	if g.Targets == nil {
		g.Targets = []string{}
	}
	return g, nil
}

func listPortalDestGroups(db *sql.DB, scope string) []PortalDestGroup {
	out := []PortalDestGroup{}
	rows, err := db.Query(`SELECT `+destGroupCols+` FROM portal_dest_groups WHERE edge_name=? ORDER BY name`, scope)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if g, err := scanDestGroup(rows); err == nil {
			out = append(out, g)
		}
	}
	return out
}

func (h *PortalHandler) listDestGroups(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	jsonOK(w, map[string]any{"groups": listPortalDestGroups(h.DB, h.scope(edge))})
}

func (h *PortalHandler) getDestGroup(w http.ResponseWriter, r *http.Request, id string) {
	g, err := scanDestGroup(h.DB.QueryRow(`SELECT `+destGroupCols+` FROM portal_dest_groups WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, g)
}

// saveDestGroup crée (id vide) ou met à jour un groupe de destinations, puis pousse la config.
func (h *PortalHandler) saveDestGroup(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Targets     *[]string `json:"targets"`
		EdgeName    string    `json:"edge_name"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	name := strings.TrimSpace(body.Name)
	if name == "" || len(name) > 80 {
		http.Error(w, "nom du groupe requis (80 caractères max)", http.StatusBadRequest)
		return
	}
	var cur PortalDestGroup
	scope := ""
	if id == "" {
		edge := strings.TrimSpace(body.EdgeName)
		if edge == "" {
			edge = portalEdgeParam(r)
		}
		if edge == "" {
			writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
			return
		}
		scope = h.scope(edge)
		id = uuid.NewString()
		cur = PortalDestGroup{ID: id, EdgeName: scope, Targets: []string{}}
	} else {
		var err error
		cur, err = scanDestGroup(h.DB.QueryRow(`SELECT `+destGroupCols+` FROM portal_dest_groups WHERE id=?`, id))
		if errors.Is(err, sql.ErrNoRows) {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
		scope = cur.EdgeName
	}
	var dup int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM portal_dest_groups WHERE edge_name=? AND LOWER(name)=LOWER(?) AND id<>?`, scope, name, id).Scan(&dup)
	if dup > 0 {
		http.Error(w, "un groupe de destinations porte déjà ce nom", http.StatusConflict)
		return
	}
	targets := cur.Targets
	if body.Targets != nil {
		known := map[string]bool{}
		for _, c := range listDestinationsAsCatalog(h.DB, scope) {
			known[c.ID] = true
		}
		targets = keepKnown(*body.Targets, known)
		if targets == nil {
			targets = []string{}
		}
	}
	targetsJSON, _ := json.Marshal(targets)
	if _, err := h.DB.Exec(`INSERT INTO portal_dest_groups (id, edge_name, name, description, targets_json) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description,
		targets_json=excluded.targets_json, updated_at=CURRENT_TIMESTAMP`,
		id, scope, name, strings.TrimSpace(body.Description), string(targetsJSON)); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "save", "portal_dest_group", name)
	h.pushScope(r.Context(), scope)
	h.getDestGroup(w, r, id)
}

// deleteDestGroup supprime le groupe et le retire des entrées qui l'utilisaient.
func (h *PortalHandler) deleteDestGroup(w http.ResponseWriter, r *http.Request, id string) {
	g, err := scanDestGroup(h.DB.QueryRow(`SELECT `+destGroupCols+` FROM portal_dest_groups WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if _, err := h.DB.Exec(`DELETE FROM portal_dest_groups WHERE id=?`, id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	cfg := loadPortalConfig(h.DB, g.EdgeName)
	changed := false
	for i, v := range cfg.Views {
		kept := keepNot(v.DestGroups, id)
		if len(kept) != len(v.DestGroups) {
			cfg.Views[i].DestGroups = kept
			changed = true
		}
	}
	if changed {
		if raw, err := json.Marshal(cfg); err == nil {
			_ = admindb.SetSetting(h.DB, settingPortalConfigPrefix+g.EdgeName, string(raw))
		}
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_dest_group", g.Name)
	h.pushScope(r.Context(), g.EdgeName)
	w.WriteHeader(http.StatusNoContent)
}

func keepNot(in []string, drop string) []string {
	var out []string
	for _, x := range in {
		if x != drop {
			out = append(out, x)
		}
	}
	return out
}

// removeDestFromGroups retire une destination supprimée de tous les groupes de la portée.
func removeDestFromGroups(db *sql.DB, scope, destID string) {
	for _, g := range listPortalDestGroups(db, scope) {
		kept := keepNot(g.Targets, destID)
		if len(kept) == len(g.Targets) {
			continue
		}
		if kept == nil {
			kept = []string{}
		}
		raw, _ := json.Marshal(kept)
		_, _ = db.Exec(`UPDATE portal_dest_groups SET targets_json=?, updated_at=CURRENT_TIMESTAMP WHERE id=?`, string(raw), g.ID)
	}
}
