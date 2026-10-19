// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

const (
	maintenanceInterval = time.Minute
	// incrementalVacuumPages rend au système au plus ~40 Mo (pages de 4 Ko) par passage : la purge
	// quotidienne des logs libère des pages, mais un fichier qui rétrécit d'un coup bloquerait les écritures.
	incrementalVacuumPages = 10000
)

// StartMaintenance garde admin.db et son WAL à une taille raisonnable.
//
// Le point de contrôle automatique de SQLite ne recycle le WAL que si, à un instant donné, aucune
// lecture n'est en cours. Des tableaux de bord rafraîchis toutes les quelques secondes sur un pool de
// 10 connexions ne laissent jamais ce créneau : le WAL grossit sans limite (16 Go constatés pour une
// base de 5 Go). TRUNCATE attend la fin des lectures en cours, bloque brièvement les nouvelles
// écritures le temps de recopier le WAL dans la base, puis le tronque.
func StartMaintenance(ctx context.Context, db *sql.DB, log *slog.Logger) {
	go func() {
		t := time.NewTicker(maintenanceInterval)
		defer t.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-t.C:
				maintain(ctx, db, log)
			}
		}
	}()
}

func maintain(ctx context.Context, db *sql.DB, log *slog.Logger) {
	var busy, walPages, moved int
	if err := db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &walPages, &moved); err != nil {
		log.Warn("sqlite: point de contrôle WAL en échec", "err", err)
	} else if busy != 0 {
		log.Warn("sqlite: point de contrôle WAL incomplet (lecture en cours), nouvel essai à la prochaine passe", "wal_pages", walPages, "recopiées", moved)
	}
	// Sans effet tant que la base n'est pas en auto_vacuum incrémental (voir docs/sauvegardes.md).
	if _, err := db.ExecContext(ctx, `PRAGMA incremental_vacuum(?)`, incrementalVacuumPages); err != nil {
		log.Warn("sqlite: incremental_vacuum en échec", "err", err)
	}
}
