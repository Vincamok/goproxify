// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"encoding/json"
	"os"

	"github.com/vincamok/goproxify/internal/config"
)

// backupConfigFiles : fichiers de configuration ajoutés à la section secrets d'un snapshot.
// La config HA effective est sauvegardée telle que lue (fichier + variables GPX_*), car elle
// peut ne venir que de l'environnement.
func (s *Server) backupConfigFiles() map[string][]byte {
	out := map[string][]byte{}
	if ha, err := json.MarshalIndent(s.cfg.HA, "", "  "); err == nil {
		out["admin-ha.json"] = ha
	}
	if p := config.AdminConfigPath(); p != "" {
		if data, err := os.ReadFile(p); err == nil {
			out["admin.json"] = data
		}
	}
	return out
}
