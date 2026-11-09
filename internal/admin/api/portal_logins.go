// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"
	"strings"
	"time"

	"github.com/google/uuid"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/portal"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// Logins préconfigurés du portail (ADR 0025). L'Admin garde leur description (nom, identifiant, droit d'usage, destinations
// liées) et le secret **scellé pour la passerelle** : il ne le voit jamais en clair, ne le renvoie jamais, et le pousse tel
// quel. Un login sans secret scellé existe mais n'est pas poussé : la passerelle ne le propose pas.

const loginsPath = "/api/v1/portal/logins"

const settingLoginPubKeyPrefix = "portal.login_pubkey."

// PortalLogin est un login préconfiguré tel que l'API le rend.
type PortalLogin struct {
	ID            string   `json:"id"`
	EdgeName      string   `json:"edge_name"`
	Name          string   `json:"name"`
	Username      string   `json:"username"`
	HasSecret     bool     `json:"has_secret"`
	HasPassword   bool     `json:"has_password"`
	HasPrivateKey bool     `json:"has_private_key"`
	AllUsers      bool     `json:"all_users"`
	Groups        []string `json:"groups"`
	Tags          []string `json:"tags"`
	DestIDs       []string `json:"dest_ids"`
	DestGroups    []string `json:"dest_groups"`
	Enabled       bool     `json:"enabled"`
	UpdatedAt     string   `json:"updated_at,omitempty"`
}

type loginRow struct {
	PortalLogin
	sealed string
}

const loginCols = `id, edge_name, name, username, secret_sealed, has_password, has_key, all_users, groups_json, tags_json,
	dest_ids_json, dest_groups_json, enabled, updated_at`

func scanLogin(s scanner) (loginRow, error) {
	var l loginRow
	var hp, hk, all, en int
	var groups, tags, dests, dgroups string
	if err := s.Scan(&l.ID, &l.EdgeName, &l.Name, &l.Username, &l.sealed, &hp, &hk, &all, &groups, &tags, &dests, &dgroups, &en, &l.UpdatedAt); err != nil {
		return l, err
	}
	l.HasSecret, l.HasPassword, l.HasPrivateKey = l.sealed != "", hp != 0, hk != 0
	l.AllUsers, l.Enabled = all != 0, en != 0
	_ = json.Unmarshal([]byte(groups), &l.Groups)
	_ = json.Unmarshal([]byte(tags), &l.Tags)
	_ = json.Unmarshal([]byte(dests), &l.DestIDs)
	_ = json.Unmarshal([]byte(dgroups), &l.DestGroups)
	l.Tags = normalizeTags(l.Tags)
	l.Groups, l.DestIDs, l.DestGroups = nonNil(cleanIDs(l.Groups)), nonNil(cleanIDs(l.DestIDs)), nonNil(cleanIDs(l.DestGroups))
	return l, nil
}

func nonNil(s []string) []string {
	if s == nil {
		return []string{}
	}
	return s
}

func listLogins(db *sql.DB, scope string) ([]loginRow, error) {
	q := `SELECT ` + loginCols + ` FROM portal_logins`
	var rows *sql.Rows
	var err error
	if scope != "" {
		rows, err = db.Query(q+` WHERE edge_name=? ORDER BY name`, scope)
	} else {
		rows, err = db.Query(q + ` ORDER BY edge_name, name`)
	}
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []loginRow
	for rows.Next() {
		if l, err := scanLogin(rows); err == nil {
			out = append(out, l)
		}
	}
	return out, rows.Err()
}

// sharedLoginsForPush construit ce que la passerelle reçoit : les logins actifs qui ont un secret scellé, leurs groupes Access
// développés en identités et leurs groupes de destinations en identifiants. La liste est toujours non nulle : vide, elle
// retire les logins que la passerelle connaissait.
func sharedLoginsForPush(db *sql.DB, scope string) []portal.SharedLogin {
	out := []portal.SharedLogin{}
	logins, err := listLogins(db, scope)
	if err != nil {
		return out
	}
	members := map[string][]string{}
	for _, g := range listPortalGroups(db, scope) {
		members[g.ID] = g.Members
	}
	destGroups := map[string][]string{}
	for _, g := range listPortalDestGroups(db, scope) {
		destGroups[g.ID] = g.Targets
	}
	for _, l := range logins {
		if !l.Enabled || l.sealed == "" {
			continue
		}
		ids := append([]string{}, l.DestIDs...)
		for _, gid := range l.DestGroups {
			ids = append(ids, destGroups[gid]...)
		}
		var who []string
		for _, gid := range l.Groups {
			who = append(who, members[gid]...)
		}
		out = append(out, portal.SharedLogin{
			ID: l.ID, Name: l.Name, Username: l.Username, Sealed: l.sealed,
			AllUsers: l.AllUsers, Members: normalizeTags(who), Tags: l.Tags, DestIDs: cleanIDs(ids),
		})
	}
	return out
}

// removeDestFromLogins retire une destination supprimée des liaisons directes des logins de la portée.
func removeDestFromLogins(db *sql.DB, scope, destID string) {
	logins, err := listLogins(db, scope)
	if err != nil {
		return
	}
	for _, l := range logins {
		kept := keepNot(l.DestIDs, destID)
		if len(kept) == len(l.DestIDs) {
			continue
		}
		raw, _ := json.Marshal(nonNil(kept))
		_, _ = db.Exec(`UPDATE portal_logins SET dest_ids_json=?, updated_at=? WHERE id=?`, string(raw), sqltime.Format(time.Now().UTC()), l.ID)
	}
}

func (h *PortalHandler) handleLogins(w http.ResponseWriter, r *http.Request) {
	rest := strings.Trim(strings.TrimPrefix(r.URL.Path, loginsPath), "/")
	switch {
	case rest == "pubkey" && r.Method == http.MethodGet:
		h.loginPubKey(w, r)
	case rest == "" && r.Method == http.MethodGet:
		h.listLoginsAPI(w, r)
	case rest == "" && r.Method == http.MethodPost:
		h.saveLogin(w, r, "")
	case rest != "" && r.Method == http.MethodGet:
		h.getLogin(w, r, rest)
	case rest != "" && r.Method == http.MethodPut:
		h.saveLogin(w, r, rest)
	case rest != "" && r.Method == http.MethodDelete:
		h.deleteLogin(w, r, rest)
	default:
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
	}
}

func (h *PortalHandler) listLoginsAPI(w http.ResponseWriter, r *http.Request) {
	list, err := listLogins(h.DB, h.scope(portalEdgeParam(r)))
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	out := make([]PortalLogin, 0, len(list))
	for _, l := range list {
		out = append(out, l.PortalLogin)
	}
	jsonOK(w, map[string]any{"logins": out})
}

func (h *PortalHandler) getLogin(w http.ResponseWriter, r *http.Request, id string) {
	l, err := scanLogin(h.DB.QueryRow(`SELECT `+loginCols+` FROM portal_logins WHERE id=?`, id))
	if err == sql.ErrNoRows {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	jsonOK(w, l.PortalLogin)
}

type loginBody struct {
	EdgeName   string    `json:"edge_name"`
	Edge       string    `json:"edge"`
	Name       *string   `json:"name"`
	Username   *string   `json:"username"`
	Sealed     *string   `json:"sealed"`
	HasPass    *bool     `json:"has_password"`
	HasKey     *bool     `json:"has_private_key"`
	AllUsers   *bool     `json:"all_users"`
	Groups     *[]string `json:"groups"`
	Tags       *[]string `json:"tags"`
	DestIDs    *[]string `json:"dest_ids"`
	DestGroups *[]string `json:"dest_groups"`
	Enabled    *bool     `json:"enabled"`
}

// saveLogin crée (id vide) ou modifie un login. Un secret scellé absent est conservé. L'Admin ne peut pas ouvrir l'enveloppe :
// il en contrôle seulement la forme.
func (h *PortalHandler) saveLogin(w http.ResponseWriter, r *http.Request, id string) {
	var b loginBody
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&b); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.bad_json")
		return
	}
	var cur loginRow
	if id != "" {
		var err error
		cur, err = scanLogin(h.DB.QueryRow(`SELECT `+loginCols+` FROM portal_logins WHERE id=?`, id))
		if err == sql.ErrNoRows {
			writeErr(w, r, http.StatusNotFound, "api.err.not_found")
			return
		}
		if err != nil {
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
		if s := h.scope(strings.TrimSpace(firstNonEmpty(b.EdgeName, b.Edge))); s != "" && s != cur.EdgeName {
			http.Error(w, "la passerelle d'un login ne se modifie pas : en créer un autre", http.StatusBadRequest)
			return
		}
	} else {
		cur.EdgeName = h.scope(strings.TrimSpace(firstNonEmpty(b.EdgeName, b.Edge)))
		cur.Enabled = true
		if cur.EdgeName == "" {
			http.Error(w, "edge_name requis", http.StatusBadRequest)
			return
		}
	}
	if b.Name != nil {
		cur.Name = strings.TrimSpace(*b.Name)
	}
	if b.Username != nil {
		cur.Username = strings.TrimSpace(*b.Username)
	}
	if cur.Username == "" {
		http.Error(w, "username requis (identifiant SSH)", http.StatusBadRequest)
		return
	}
	if cur.Name == "" {
		cur.Name = cur.Username
	}
	if b.Sealed != nil {
		if *b.Sealed == "" {
			cur.sealed, cur.HasPassword, cur.HasPrivateKey = "", false, false
		} else {
			if err := portal.ValidSealedSecret(*b.Sealed); err != nil {
				http.Error(w, "secret scellé invalide : "+err.Error()+" (le secret doit être chiffré avec la clé publique de la passerelle, jamais envoyé en clair)", http.StatusBadRequest)
				return
			}
			cur.sealed = *b.Sealed
			cur.HasPassword, cur.HasPrivateKey = b.HasPass != nil && *b.HasPass, b.HasKey != nil && *b.HasKey
		}
	}
	if b.AllUsers != nil {
		cur.AllUsers = *b.AllUsers
	}
	if b.Groups != nil {
		cur.Groups = cleanIDs(*b.Groups)
	}
	if b.Tags != nil {
		cur.Tags = normalizeTags(*b.Tags)
	}
	if b.DestIDs != nil {
		cur.DestIDs = cleanIDs(*b.DestIDs)
	}
	if b.DestGroups != nil {
		cur.DestGroups = cleanIDs(*b.DestGroups)
	}
	if b.Enabled != nil {
		cur.Enabled = *b.Enabled
	}
	var dup int
	_ = h.DB.QueryRow(`SELECT COUNT(*) FROM portal_logins WHERE edge_name=? AND LOWER(name)=LOWER(?) AND id<>?`, cur.EdgeName, cur.Name, id).Scan(&dup)
	if dup > 0 {
		http.Error(w, "un login de ce nom existe déjà sur cette passerelle", http.StatusConflict)
		return
	}

	groups, _ := json.Marshal(nonNil(cur.Groups))
	tags, _ := json.Marshal(nonNil(cur.Tags))
	dests, _ := json.Marshal(nonNil(cur.DestIDs))
	dgroups, _ := json.Marshal(nonNil(cur.DestGroups))
	now := sqltime.Format(time.Now().UTC())
	action := "update"
	if id == "" {
		id, action = uuid.New().String(), "create"
		_, err := h.DB.Exec(`INSERT INTO portal_logins (id, edge_name, name, username, secret_sealed, has_password, has_key, all_users, groups_json, tags_json, dest_ids_json, dest_groups_json, enabled, created_at, updated_at)
			VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`, id, cur.EdgeName, cur.Name, cur.Username, cur.sealed, boolInt(cur.HasPassword), boolInt(cur.HasPrivateKey),
			boolInt(cur.AllUsers), string(groups), string(tags), string(dests), string(dgroups), boolInt(cur.Enabled), now, now)
		if err != nil {
			h.Log.Error("portal login create", "err", err)
			writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
			return
		}
	} else if _, err := h.DB.Exec(`UPDATE portal_logins SET name=?, username=?, secret_sealed=?, has_password=?, has_key=?, all_users=?, groups_json=?, tags_json=?, dest_ids_json=?, dest_groups_json=?, enabled=?, updated_at=? WHERE id=?`,
		cur.Name, cur.Username, cur.sealed, boolInt(cur.HasPassword), boolInt(cur.HasPrivateKey), boolInt(cur.AllUsers),
		string(groups), string(tags), string(dests), string(dgroups), boolInt(cur.Enabled), now, id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), action, "portal_login", id)
	h.pushScope(r.Context(), cur.EdgeName)
	saved, _ := scanLogin(h.DB.QueryRow(`SELECT `+loginCols+` FROM portal_logins WHERE id=?`, id))
	if action == "create" {
		w.WriteHeader(http.StatusCreated)
	}
	jsonOK(w, saved.PortalLogin)
}

func (h *PortalHandler) deleteLogin(w http.ResponseWriter, r *http.Request, id string) {
	var edge string
	if err := h.DB.QueryRow(`SELECT edge_name FROM portal_logins WHERE id=?`, id).Scan(&edge); err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
		return
	}
	if _, err := h.DB.Exec(`DELETE FROM portal_logins WHERE id=?`, id); err != nil {
		writeErr(w, r, http.StatusInternalServerError, "api.err.internal")
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "delete", "portal_login", id)
	h.pushScope(r.Context(), edge)
	w.WriteHeader(http.StatusNoContent)
}

// loginPubKey rend la clé publique de scellement de la passerelle : le navigateur ou la CLI chiffre le secret avec elle avant
// de l'envoyer. Lue sur la passerelle à chaque fois, gardée pour le cas où elle serait hors ligne (la clé ne change qu'avec sa
// clé maître).
func (h *PortalHandler) loginPubKey(w http.ResponseWriter, r *http.Request) {
	scope := h.scope(portalEdgeParam(r))
	if scope == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.edge_required")
		return
	}
	key, err := h.fetchLoginPubKey(r.Context(), scope)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadGateway)
		return
	}
	jsonOK(w, map[string]string{"public_key": key})
}

func (h *PortalHandler) fetchLoginPubKey(ctx context.Context, scope string) (string, error) {
	cacheKey := settingLoginPubKeyPrefix + scope
	client := edgeproxy.NewClient()
	var lastErr error
	for _, t := range h.scopeTargets(ctx, scope) {
		key, err := client.PortalLoginPubKey(ctx, t)
		if err != nil {
			lastErr = err
			continue
		}
		if admindb.GetSetting(h.DB, cacheKey, "") != key {
			_ = admindb.SetSetting(h.DB, cacheKey, key)
		}
		return key, nil
	}
	if cached := admindb.GetSetting(h.DB, cacheKey, ""); cached != "" {
		return cached, nil
	}
	if lastErr != nil {
		return "", lastErr
	}
	return "", errStr("aucune passerelle joignable pour fournir la clé de scellement")
}
