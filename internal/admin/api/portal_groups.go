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
	"github.com/vincamok/goproxify/internal/edge/portal"
)

// PortalGroup est un groupe d'utilisateurs du portail, propre à une passerelle (ou à son groupe HA).
// Il sert à donner des droits sur une entrée du portail (/prestataire, /interne…).
type PortalGroup struct {
	ID          string   `json:"id"`
	EdgeName    string   `json:"edge_name"`
	Name        string   `json:"name"`
	Description string   `json:"description,omitempty"`
	Members     []string `json:"members"` // identifiants de connexion (email ou identifiant d'annuaire), en minuscules
}

func (h *PortalHandler) handleGroups(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/portal/groups"), "/")
	switch {
	case rest == "" && r.Method == http.MethodGet:
		h.listGroups(w, r)
	case rest == "" && r.Method == http.MethodPost:
		h.saveGroup(w, r, "")
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodGet:
		h.getGroup(w, r, rest)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodPut:
		h.saveGroup(w, r, rest)
	case rest != "" && !strings.Contains(rest, "/") && r.Method == http.MethodDelete:
		h.deleteGroup(w, r, rest)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func scanPortalGroup(row scannable) (PortalGroup, error) {
	var g PortalGroup
	var members string
	if err := row.Scan(&g.ID, &g.EdgeName, &g.Name, &g.Description, &members); err != nil {
		return g, err
	}
	_ = json.Unmarshal([]byte(members), &g.Members)
	if g.Members == nil {
		g.Members = []string{}
	}
	return g, nil
}

const portalGroupCols = `id, edge_name, name, description, members_json`

func listPortalGroups(db *sql.DB, scope string) []PortalGroup {
	out := []PortalGroup{}
	rows, err := db.Query(`SELECT `+portalGroupCols+` FROM portal_groups WHERE edge_name=? ORDER BY name`, scope)
	if err != nil {
		return out
	}
	defer rows.Close()
	for rows.Next() {
		if g, err := scanPortalGroup(rows); err == nil {
			out = append(out, g)
		}
	}
	return out
}

func (h *PortalHandler) listGroups(w http.ResponseWriter, r *http.Request) {
	edge := portalEdgeParam(r)
	if edge == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	jsonOK(w, map[string]any{"groups": listPortalGroups(h.DB, h.scope(edge))})
}

func (h *PortalHandler) getGroup(w http.ResponseWriter, r *http.Request, id string) {
	g, err := scanPortalGroup(h.DB.QueryRow(`SELECT `+portalGroupCols+` FROM portal_groups WHERE id=?`, id))
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

// saveGroup crée (id vide) ou met à jour un groupe, puis pousse la config à la passerelle.
func (h *PortalHandler) saveGroup(w http.ResponseWriter, r *http.Request, id string) {
	var body struct {
		Name        string    `json:"name"`
		Description string    `json:"description"`
		Members     *[]string `json:"members"`
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
	var cur PortalGroup
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
		cur = PortalGroup{ID: id, EdgeName: scope, Members: []string{}}
	} else {
		var err error
		cur, err = scanPortalGroup(h.DB.QueryRow(`SELECT `+portalGroupCols+` FROM portal_groups WHERE id=?`, id))
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
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM portal_groups WHERE edge_name=? AND LOWER(name)=LOWER(?) AND id<>?`, scope, name, id).Scan(&dup)
	if dup > 0 {
		http.Error(w, "un groupe porte déjà ce nom", http.StatusConflict)
		return
	}
	members := cur.Members
	if body.Members != nil {
		members = normalizeTags(*body.Members)
	}
	membersJSON, _ := json.Marshal(members)
	if _, err := h.DB.Exec(`INSERT INTO portal_groups (id, edge_name, name, description, members_json) VALUES (?, ?, ?, ?, ?)
		ON CONFLICT(id) DO UPDATE SET name=excluded.name, description=excluded.description,
		members_json=excluded.members_json, updated_at=CURRENT_TIMESTAMP`,
		id, scope, name, strings.TrimSpace(body.Description), string(membersJSON)); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "save", "portal_group", name)
	h.pushScope(r.Context(), scope)
	h.getGroup(w, r, id)
}

// deleteGroup supprime le groupe et le retire des entrées qui l'utilisaient.
func (h *PortalHandler) deleteGroup(w http.ResponseWriter, r *http.Request, id string) {
	g, err := scanPortalGroup(h.DB.QueryRow(`SELECT `+portalGroupCols+` FROM portal_groups WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	if _, err := h.DB.Exec(`DELETE FROM portal_groups WHERE id=?`, id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	cfg := loadPortalConfig(h.DB, g.EdgeName)
	changed := false
	for i, v := range cfg.Views {
		kept := v.Groups[:0:0]
		for _, gid := range v.Groups {
			if gid != id {
				kept = append(kept, gid)
			}
		}
		if len(kept) != len(v.Groups) {
			cfg.Views[i].Groups = kept
			changed = true
		}
	}
	if changed {
		if raw, err := json.Marshal(cfg); err == nil {
			_ = admindb.SetSetting(h.DB, settingPortalConfigPrefix+g.EdgeName, string(raw))
		}
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_group", g.Name)
	h.pushScope(r.Context(), g.EdgeName)
	w.WriteHeader(http.StatusNoContent)
}

// sanitizeViewRefs ne garde dans les entrées que des groupes et destinations qui existent dans la portée.
func sanitizeViewRefs(db *sql.DB, scope string, views []portal.View) {
	groups := map[string]bool{}
	for _, g := range listPortalGroups(db, scope) {
		groups[g.ID] = true
	}
	dests := map[string]bool{}
	for _, c := range listDestinationsAsCatalog(db, scope) {
		dests[c.ID] = true
	}
	for i := range views {
		views[i].Groups = keepKnown(views[i].Groups, groups)
		views[i].TargetIDs = keepKnown(views[i].TargetIDs, dests)
		views[i].Members, views[i].Restricted = nil, false // calculés à l'envoi
	}
}

func keepKnown(in []string, known map[string]bool) []string {
	var out []string
	for _, x := range in {
		if known[x] {
			out = append(out, x)
		}
	}
	return out
}

// resolveViewsForPush calcule, pour la passerelle, les membres autorisés de chaque entrée
// (utilisateurs listés + membres des groupes) ; les listes brutes ne sont pas envoyées.
func resolveViewsForPush(db *sql.DB, scope string, views []portal.View) []portal.View {
	if len(views) == 0 {
		return views
	}
	byID := map[string][]string{}
	for _, g := range listPortalGroups(db, scope) {
		byID[g.ID] = g.Members
	}
	out := make([]portal.View, len(views))
	for i, v := range views {
		members := append([]string(nil), v.Users...)
		for _, gid := range v.Groups {
			members = append(members, byID[gid]...)
		}
		v.Members = normalizeTags(members)
		v.Restricted = len(v.Users)+len(v.Groups) > 0
		v.Users, v.Groups = nil, nil
		out[i] = v
	}
	return out
}
