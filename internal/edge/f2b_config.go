// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"os"
	"path/filepath"

	edgef2b "github.com/vincamok/goproxify/internal/edge/fail2ban"
)

// f2bConfigPath est la copie locale chiffrée de la configuration Fail2Ban poussée par l'Admin. Elle ne
// contient aucun secret, mais toutes les configurations de la passerelle sont chiffrées au repos (ADR 0006).
func f2bConfigPath() string {
	if p := os.Getenv("GPX_F2B_CONFIG_FILE"); p != "" {
		return p
	}
	return filepath.Join(edgef2b.CfgDir(), "config.gpx")
}

// saveF2BConfig persiste la configuration reçue de l'Admin, chiffrée, et retire l'ancien fichier
// en clair une fois la copie chiffrée écrite.
func (s *Server) saveF2BConfig(cfg edgef2b.Config) error {
	if err := s.cache.SaveFile(f2bConfigPath(), cfg); err != nil {
		return err
	}
	if edgef2b.HasConfig("") {
		if err := edgef2b.RemoveConfig(""); err != nil {
			s.log.Warn("fail2ban: ancien fichier de configuration non supprimé", "err", err)
		}
	}
	return nil
}

// loadF2BConfig relit la configuration au démarrage, sans l'Admin. Un ancien fichier en clair est
// migré vers la copie chiffrée.
func (s *Server) loadF2BConfig() edgef2b.Config {
	var cfg edgef2b.Config
	ok, err := s.cache.LoadFile(f2bConfigPath(), &cfg)
	if err != nil {
		s.log.Warn("fail2ban: config locale illisible — en attente de l'Admin", "err", err)
		return edgef2b.DefaultConfig()
	}
	if ok {
		return cfg
	}
	if !edgef2b.HasConfig("") {
		return edgef2b.DefaultConfig()
	}
	cfg = edgef2b.LoadConfig("")
	if err := s.saveF2BConfig(cfg); err != nil {
		s.log.Warn("fail2ban: migration de la config vers le stockage chiffré échouée", "err", err)
	} else {
		s.log.Info("fail2ban: config migrée vers le stockage chiffré")
	}
	return cfg
}
