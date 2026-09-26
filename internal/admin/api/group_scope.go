// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"

	"github.com/vincamok/goproxify/internal/admin/archstore"
)

// GroupResolver donne le groupe HA d'une passerelle et ses membres (archstore.Store le fournit).
type GroupResolver interface {
	GroupOf(ref string) string
	GroupMembers(group string) []archstore.NodeEntry
	Groups() (names []string, members map[string][]archstore.NodeEntry)
}

const groupScopePrefix = "group:"

// scopeFor retourne la portée d'un réglage de sécurité pour la passerelle ref :
// "group:<nom>" si elle appartient à un groupe HA (la configuration est celle du groupe),
// sinon ref lui-même ; "" désigne la configuration globale.
func scopeFor(g GroupResolver, ref string) string {
	if ref == "" || g == nil {
		return ref
	}
	if name := g.GroupOf(ref); name != "" {
		return groupScopePrefix + name
	}
	return ref
}

// settingKey construit la clé settings d'un réglage pour une portée.
func settingKey(base, scope string) string {
	if scope == "" {
		return base
	}
	return base + ":" + scope
}

// readScopedSetting lit un réglage avec la chaîne : portée (groupe ou passerelle) → valeur propre
// à la passerelle (avant l'introduction des groupes) → configuration globale.
func readScopedSetting(ctx context.Context, db *sql.DB, base, scope, ref string) (string, bool) {
	keys := []string{settingKey(base, scope)}
	if ref != "" && ref != scope {
		keys = append(keys, settingKey(base, ref))
	}
	keys = append(keys, base)
	for _, k := range keys {
		var v string
		if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, k).Scan(&v); err == nil && v != "" {
			return v, true
		}
	}
	return "", false
}

// ThreatConfigKeyFor retourne la clé de la config Sentinel qui s'applique à une passerelle
// (outil MCP de simulation) : celle de son groupe, sinon la sienne.
func ThreatConfigKeyFor(g GroupResolver, ref string) string {
	return threatConfigKey(scopeFor(g, ref))
}

// groupedSettings : réglages de sécurité qui suivent le groupe HA.
var groupedSettings = []string{"threat_engine_config", "ips_provider", "server_config"}

// MigrateGroupSettings crée la valeur de groupe des réglages qui n'en ont pas encore, à partir
// de celle des membres (le premier membre du fichier qui en a une). Les valeurs propres aux
// membres sont conservées telles quelles ; un désaccord entre membres est signalé, jamais écrasé.
func MigrateGroupSettings(ctx context.Context, db *sql.DB, g GroupResolver, log *slog.Logger) {
	if g == nil {
		return
	}
	names, members := g.Groups()
	for _, group := range names {
		for _, base := range groupedSettings {
			groupKey := settingKey(base, groupScopePrefix+group)
			var exists int
			_ = db.QueryRowContext(ctx, `SELECT COUNT(*) FROM settings WHERE key=?`, groupKey).Scan(&exists)
			if exists > 0 {
				continue
			}
			var chosen, chosenFrom string
			conflicts := []string{}
			for _, n := range members[group] {
				v := memberSetting(ctx, db, base, n)
				if v == "" {
					continue
				}
				if chosen == "" {
					chosen, chosenFrom = v, n.Name
					continue
				}
				if !sameJSON(chosen, v) {
					conflicts = append(conflicts, n.Name)
				}
			}
			if chosen == "" {
				continue
			}
			if _, err := db.ExecContext(ctx,
				`INSERT INTO settings (key, value) VALUES (?, ?) ON CONFLICT(key) DO NOTHING`, groupKey, chosen); err != nil {
				log.Warn("groupes: migration réglage", "cle", groupKey, "err", err)
				continue
			}
			log.Info("groupes: réglage de groupe créé", "groupe", group, "reglage", base, "repris_de", chosenFrom)
			if len(conflicts) > 0 {
				log.Warn("groupes: valeurs différentes entre membres, celle de la première passerelle est retenue",
					"groupe", group, "reglage", base, "retenue", chosenFrom, "differentes", conflicts)
			}
		}
	}
}

func memberSetting(ctx context.Context, db *sql.DB, base string, n archstore.NodeEntry) string {
	for _, ref := range []string{n.ID, n.Name} {
		if ref == "" {
			continue
		}
		var v string
		if err := db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, settingKey(base, ref)).Scan(&v); err == nil && v != "" {
			return v
		}
	}
	return ""
}

func sameJSON(a, b string) bool {
	var ca, cb bytes.Buffer
	if json.Compact(&ca, []byte(a)) != nil || json.Compact(&cb, []byte(b)) != nil {
		return a == b
	}
	var va, vb any
	if json.Unmarshal(ca.Bytes(), &va) != nil || json.Unmarshal(cb.Bytes(), &vb) != nil {
		return ca.String() == cb.String()
	}
	ja, _ := json.Marshal(va)
	jb, _ := json.Marshal(vb)
	return bytes.Equal(ja, jb)
}
