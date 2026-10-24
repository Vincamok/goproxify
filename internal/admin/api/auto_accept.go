// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"encoding/json"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/sqltime"
)

// NodeAutoAccept indique si un nœud (declared ou ticket bootstrap) doit être
// accepté automatiquement à la connexion (wizard architecture).
func NodeAutoAccept(db *sql.DB, nodeName string) bool {
	name := strings.TrimSpace(nodeName)
	if db == nil || name == "" {
		return false
	}
	if DeclaredAutoAccept(db, name) {
		return true
	}
	return BootstrapTicketAutoAccept(db, name)
}

// DeclaredAutoAccept lit config.auto_accept des declared_nodes au nom donné.
func DeclaredAutoAccept(db *sql.DB, nodeName string) bool {
	rows, err := db.Query(`SELECT config FROM declared_nodes WHERE name=?`, nodeName)
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var cfg string
		if err := rows.Scan(&cfg); err != nil {
			continue
		}
		if configAutoAccept(cfg) {
			return true
		}
	}
	return false
}

// BootstrapTicketAutoAccept regarde les tickets non expirés dont payload.auto_accept
// est vrai et payload.node_names contient nodeName.
func BootstrapTicketAutoAccept(db *sql.DB, nodeName string) bool {
	// expires_at est au format de CURRENT_TIMESTAMP (t.String() en UTC pour les anciens tickets, même
	// préfixe) : une borne RFC3339 donnait le ticket pour expiré dès minuit UTC le jour de son expiration.
	rows, err := db.Query(`SELECT payload FROM bootstrap_tickets WHERE expires_at > ?`, sqltime.Format(time.Now()))
	if err != nil {
		return false
	}
	defer rows.Close()
	for rows.Next() {
		var raw string
		if err := rows.Scan(&raw); err != nil {
			continue
		}
		var p struct {
			AutoAccept bool     `json:"auto_accept"`
			NodeNames  []string `json:"node_names"`
		}
		if err := json.Unmarshal([]byte(raw), &p); err != nil || !p.AutoAccept {
			continue
		}
		for _, n := range p.NodeNames {
			if strings.TrimSpace(n) == nodeName {
				return true
			}
		}
	}
	return false
}

// ConsumeBootstrapTicket fait servir un ticket une seule fois : le nom du nœud en sort de la liste que le ticket couvre
// (le ticket disparaît quand elle est vide) et l'auto-acceptation que ce ticket avait posée sur le nœud déclaré tombe.
// Une auto-acceptation posée par l'opérateur sur un nœud déclaré, sans ticket, reste en place.
func ConsumeBootstrapTicket(db *sql.DB, nodeName string) {
	name := strings.TrimSpace(nodeName)
	if db == nil || name == "" {
		return
	}
	rows, err := db.Query(`SELECT token, payload FROM bootstrap_tickets WHERE expires_at > ?`, sqltime.Format(time.Now()))
	if err == nil {
		type upd struct{ token, payload string }
		var todo []upd
		var drop []string
		for rows.Next() {
			var tok, raw string
			if rows.Scan(&tok, &raw) != nil {
				continue
			}
			var p map[string]any
			if json.Unmarshal([]byte(raw), &p) != nil {
				continue
			}
			names, _ := p["node_names"].([]any)
			kept := make([]any, 0, len(names))
			found := false
			for _, n := range names {
				if s, ok := n.(string); ok && strings.TrimSpace(s) == name {
					found = true
					continue
				}
				kept = append(kept, n)
			}
			if !found {
				continue
			}
			if len(kept) == 0 {
				drop = append(drop, tok)
				continue
			}
			p["node_names"] = kept
			if b, err := json.Marshal(p); err == nil {
				todo = append(todo, upd{tok, string(b)})
			}
		}
		rows.Close()
		for _, u := range todo {
			_, _ = db.Exec(`UPDATE bootstrap_tickets SET payload=? WHERE token=?`, u.payload, u.token)
		}
		for _, tok := range drop {
			_, _ = db.Exec(`DELETE FROM bootstrap_tickets WHERE token=?`, tok)
		}
	}
	// Le drapeau posé sur le nœud déclaré par LinkBootstrapToDeclared (bootstrap_token) tombe avec le ticket.
	drows, err := db.Query(`SELECT id, config FROM declared_nodes WHERE name=?`, name)
	if err != nil {
		return
	}
	type cfgUpd struct{ id, cfg string }
	var cfgs []cfgUpd
	for drows.Next() {
		var id, cfg string
		if drows.Scan(&id, &cfg) != nil || cfg == "" {
			continue
		}
		var m map[string]any
		if json.Unmarshal([]byte(cfg), &m) != nil {
			continue
		}
		if _, linked := m["bootstrap_token"]; !linked {
			continue
		}
		delete(m, "bootstrap_token")
		m["auto_accept"] = false
		if b, err := json.Marshal(m); err == nil {
			cfgs = append(cfgs, cfgUpd{id, string(b)})
		}
	}
	drows.Close()
	for _, c := range cfgs {
		_, _ = db.Exec(`UPDATE declared_nodes SET config=? WHERE id=?`, c.cfg, c.id)
	}
}

// LinkBootstrapToDeclared attache bootstrap_token + auto_accept aux declared_nodes
// dont le nom figure dans names.
func LinkBootstrapToDeclared(db *sql.DB, token string, names []string) {
	if db == nil || token == "" || len(names) == 0 {
		return
	}
	for _, name := range names {
		name = strings.TrimSpace(name)
		if name == "" {
			continue
		}
		var cfg string
		err := db.QueryRow(`SELECT config FROM declared_nodes WHERE name=? ORDER BY created_at DESC LIMIT 1`, name).Scan(&cfg)
		if err != nil {
			continue
		}
		var m map[string]any
		if cfg == "" {
			m = map[string]any{}
		} else if err := json.Unmarshal([]byte(cfg), &m); err != nil {
			m = map[string]any{}
		}
		m["auto_accept"] = true
		m["bootstrap_token"] = token
		b, err := json.Marshal(m)
		if err != nil {
			continue
		}
		_, _ = db.Exec(`UPDATE declared_nodes SET config=? WHERE name=?`, string(b), name)
	}
}

func configAutoAccept(cfg string) bool {
	if cfg == "" {
		return false
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(cfg), &m); err != nil {
		return false
	}
	switch v := m["auto_accept"].(type) {
	case bool:
		return v
	case float64:
		return v != 0
	case string:
		s := strings.ToLower(strings.TrimSpace(v))
		return s == "1" || s == "true" || s == "yes"
	default:
		return false
	}
}
