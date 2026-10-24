// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/vincamok/goproxify/internal/config"
	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/logexport"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// logSignKeyPath est la copie locale chiffrée de la clé qui signe les exports de logs. Elle est à la racine du
// volume, donc dans la sauvegarde d'état : sans elle, les exports déjà remis ne se vérifieraient plus avec la clé
// publique qu'on a relevée.
func logSignKeyPath() string {
	if p := os.Getenv("GPX_LOG_SIGN_KEY_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/log-sign-key.gpx"
}

// logExportAuditPath est le journal local des exports et des gels légaux.
func logExportAuditPath() string {
	if p := os.Getenv("GPX_LOG_EXPORT_AUDIT_PATH"); p != "" {
		return p
	}
	return "/etc/goproxify/log-export-audit.jsonl"
}

// LocalLogs est ce qu'une commande locale utilise pour exporter les logs d'une passerelle, Admin éteint.
type LocalLogs struct {
	// Store est la base de logs, ouverte en lecture seule : ni écriture, ni purge, quelle que soit la rétention
	// que cette commande ignore.
	Store   *logstore.Store
	Cache   *edgecache.Store
	Audit   logexport.Audit
	KeyPath string
}

// OpenLocalLogs ouvre la base de logs d'une passerelle avec ses clés locales. Une clé de pseudonymisation présente mais
// illisible est une erreur : l'export rendrait silencieusement des IP tronquées.
func OpenLocalLogs(cfg *config.EdgeConfig) (*LocalLogs, error) {
	cachePath := "/etc/goproxify/edge-cache.gpx"
	if p := os.Getenv("GPX_EDGE_CACHE_PATH"); p != "" {
		cachePath = p
	}
	cache := edgecache.New(cachePath, edgecache.ResolveSecret(cfg.ControlPlane.AuthToken))
	var kf logIPKeyFile
	if _, err := cache.LoadFile(logIPKeyPath(), &kf); err != nil {
		return nil, fmt.Errorf("clé de pseudonymisation illisible (%s) : le secret d'appairage a-t-il changé ? %w", logIPKeyPath(), err)
	}
	dir := cfg.Engine.LogStoreDir
	if dir == "" {
		dir = defaultLogStoreDir
	}
	if _, err := os.Stat(dir); err != nil {
		return nil, fmt.Errorf("dossier de logs introuvable (%s) : %w", filepath.Clean(dir), err)
	}
	st, err := logstore.Open(logstore.Options{Dir: dir, IPKey: kf.Key, ReadOnly: true})
	if err != nil {
		return nil, err
	}
	return &LocalLogs{Store: st, Cache: cache, Audit: logexport.Audit{Path: logExportAuditPath()}, KeyPath: logSignKeyPath()}, nil
}
