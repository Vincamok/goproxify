// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"os"
	"path/filepath"

	edgecrowdsec "github.com/vincamok/goproxify/internal/edge/crowdsec"
)

// crowdSecConfigPath est la copie locale chiffrée de la configuration CrowdSec poussée par l'Admin. Elle
// contient la clé d'API du bouncer : l'ancien fichier config.json la gardait en clair.
func crowdSecConfigPath() string {
	if p := os.Getenv("GPX_CROWDSEC_CONFIG_PATH"); p != "" {
		return p
	}
	return filepath.Join(edgecrowdsec.Dir(), "config.gpx")
}

// saveCrowdSecConfig persiste la configuration reçue de l'Admin, chiffrée, et retire l'ancien fichier
// en clair une fois la copie chiffrée écrite.
func (s *Server) saveCrowdSecConfig(cfg edgecrowdsec.Config) error {
	if err := s.cache.SaveFile(crowdSecConfigPath(), cfg); err != nil {
		return err
	}
	if edgecrowdsec.HasConfig("") {
		if err := edgecrowdsec.RemoveConfig(""); err != nil {
			s.log.Warn("crowdsec: ancien fichier de configuration non supprimé", "err", err)
		}
	}
	return nil
}

// loadCrowdSecConfig relit la configuration au démarrage, sans l'Admin. Un ancien fichier en clair est
// migré vers la copie chiffrée.
func (s *Server) loadCrowdSecConfig() edgecrowdsec.Config {
	var cfg edgecrowdsec.Config
	ok, err := s.cache.LoadFile(crowdSecConfigPath(), &cfg)
	if err != nil {
		s.log.Warn("crowdsec: config locale illisible — en attente de l'Admin", "err", err)
		return edgecrowdsec.DefaultConfig()
	}
	if ok {
		return cfg
	}
	if !edgecrowdsec.HasConfig("") {
		return edgecrowdsec.DefaultConfig()
	}
	cfg = edgecrowdsec.LoadConfig("")
	if err := s.saveCrowdSecConfig(cfg); err != nil {
		s.log.Warn("crowdsec: migration de la config vers le stockage chiffré échouée", "err", err)
	} else {
		s.log.Info("crowdsec: config migrée vers le stockage chiffré")
	}
	return cfg
}
