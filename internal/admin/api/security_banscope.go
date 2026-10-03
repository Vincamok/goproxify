// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"database/sql"
	"fmt"
	"strings"
)

// NormalizeBanScope valide la portée d'un ban : "" (toutes les passerelles), le nom d'une passerelle
// enregistrée ou "group:<nom>" pour un groupe HA existant. Un id de jeton est ramené au nom du nœud,
// car les passerelles reçoivent leurs bans selon leur nom.
func NormalizeBanScope(db *sql.DB, groups GroupResolver, raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", nil
	}
	if name, ok := strings.CutPrefix(raw, groupScopePrefix); ok {
		if groups != nil {
			names, _ := groups.Groups()
			for _, n := range names {
				if n == name {
					return raw, nil
				}
			}
		}
		return "", fmt.Errorf("groupe HA inconnu %q", name)
	}
	var node string
	if db.QueryRow(`SELECT node_name FROM tokens WHERE (id=? OR node_name=?) AND node_name<>'' LIMIT 1`, raw, raw).Scan(&node) == nil {
		return node, nil
	}
	return "", fmt.Errorf("passerelle inconnue %q (nom d'une passerelle enregistrée ou group:<nom>)", raw)
}
