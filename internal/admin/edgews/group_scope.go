// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"strings"
)

const groupScopePrefix = "group:"

// groupOf retourne le groupe HA de la passerelle (config du wizard dans architecture.json).
func (m *Manager) groupOf(e *edgeEntry) string {
	if m.archStore == nil {
		return ""
	}
	if g := m.archStore.GroupOf(e.id); g != "" {
		return g
	}
	return m.archStore.GroupOf(e.nodeName)
}

// entriesFor retourne les passerelles visées par une portée : toutes ("" ), les membres d'un
// groupe HA ("group:<nom>") ou une passerelle (nom ou id).
func (m *Manager) entriesFor(scope string) []*edgeEntry {
	all := m.allEntries()
	if scope == "" {
		return all
	}
	var out []*edgeEntry
	if group, ok := strings.CutPrefix(scope, groupScopePrefix); ok {
		for _, e := range all {
			if m.groupOf(e) == group {
				out = append(out, e)
			}
		}
		return out
	}
	for _, e := range all {
		if e.nodeName == scope || e.id == scope {
			out = append(out, e)
		}
	}
	return out
}

// scopedSetting lit un réglage de sécurité pour une passerelle, dans l'ordre : valeur du groupe HA,
// valeur propre à la passerelle (avant l'introduction des groupes), configuration globale.
func (m *Manager) scopedSetting(ctx context.Context, base string, e *edgeEntry) string {
	keys := []string{}
	if g := m.groupOf(e); g != "" {
		keys = append(keys, base+":"+groupScopePrefix+g)
	}
	keys = append(keys, base+":"+e.id, base+":"+e.nodeName, base)
	for _, k := range keys {
		var v string
		if err := m.db.QueryRowContext(ctx, `SELECT value FROM settings WHERE key=?`, k).Scan(&v); err == nil && v != "" {
			return v
		}
	}
	return ""
}
