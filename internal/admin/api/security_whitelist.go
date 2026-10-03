// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/security"
)

// whitelistView est une entrée de la liste blanche avec l'effet qu'elle a sur les bans actifs.
type whitelistView struct {
	security.WhitelistEntry
	// BansExempted : bans actifs entièrement couverts par l'entrée, donc sans effet sur ces adresses.
	BansExempted int `json:"bans_exempted"`
}

// activeBanPrefixes retourne les cibles des bans actifs.
func activeBanPrefixes(db *sql.DB, r *http.Request) []string {
	rows, err := db.QueryContext(r.Context(),
		`SELECT ip FROM security_bans WHERE expires_at IS NULL OR expires_at = '' OR datetime(expires_at) > CURRENT_TIMESTAMP`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if rows.Scan(&ip) == nil {
			out = append(out, ip)
		}
	}
	return out
}

func whitelistViews(db *sql.DB, r *http.Request) []whitelistView {
	entries := security.LoadWhitelist(db)
	bans := activeBanPrefixes(db, r)
	out := make([]whitelistView, 0, len(entries))
	for _, e := range entries {
		v := whitelistView{WhitelistEntry: e}
		if ep, err := security.ParseTraceTarget(e.Value); err == nil {
			for _, b := range bans {
				if bp, err := security.ParseTraceTarget(b); err == nil && ep.Bits() <= bp.Bits() && ep.Contains(bp.Addr()) {
					v.BansExempted++
				}
			}
		}
		out = append(out, v)
	}
	return out
}

// whitelistList : GET /api/v1/security/bans/whitelist
func (h *SecurityHandler) whitelistList(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, whitelistViews(h.DB, r))
}

// whitelistAdd : POST /api/v1/security/bans/whitelist {"ip": "<ip|cidr>", "comment": "…"}
func (h *SecurityHandler) whitelistAdd(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IP      string `json:"ip"`
		Comment string `json:"comment"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	t, err := security.ParseBanTarget(body.IP)
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	entry, added, covering, err := security.AddWhitelist(h.DB, t, body.Comment, actorName(r))
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if !added {
		jsonOK(w, map[string]any{"added": false, "covered_by": covering.Value})
		return
	}
	if h.OnWhitelistChange != nil {
		h.OnWhitelistChange()
	}
	var view whitelistView
	for _, v := range whitelistViews(h.DB, r) {
		if v.Value == entry.Value {
			view = v
		}
	}
	w.WriteHeader(http.StatusCreated)
	jsonOK(w, map[string]any{"added": true, "entry": view})
}

// whitelistRemove : DELETE /api/v1/security/bans/whitelist?ip=<valeur enregistrée>
func (h *SecurityHandler) whitelistRemove(w http.ResponseWriter, r *http.Request) {
	t, err := security.ParseBanTarget(r.URL.Query().Get("ip"))
	if err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	found, err := security.RemoveWhitelist(h.DB, t)
	if err != nil {
		secJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	if !found {
		http.Error(w, "entrée introuvable : "+t.Value, http.StatusNotFound)
		return
	}
	if h.OnWhitelistChange != nil {
		h.OnWhitelistChange()
	}
	w.WriteHeader(http.StatusNoContent)
}

func actorName(r *http.Request) string {
	if a := auth.ActorFromContext(r.Context()); a != "" {
		return a
	}
	return ""
}
