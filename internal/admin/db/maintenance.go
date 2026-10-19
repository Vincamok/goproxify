// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"context"
	"database/sql"
	"fmt"
	"log/slog"
	"sync/atomic"
	"time"
)

// lastWALPages : taille du WAL relevée à la passe précédente.
var lastWALPages atomic.Int64

// checkpointTimeout choisit le délai d'attente des lecteurs selon la taille du WAL à la passe précédente.
func checkpointTimeout(walPages int64) time.Duration {
	if walPages*4096 > walForceBytes {
		return 10 * time.Second
	}
	return checkpointBusyTimeout
}

const (
	maintenanceInterval = time.Minute
	// incrementalVacuumPages rend au système au plus ~40 Mo (pages de 4 Ko) par passage : la purge
	// quotidienne des logs libère des pages, mais un fichier qui rétrécit d'un coup bloquerait les écritures.
	incrementalVacuumPages = 10000
	// checkpointBusyTimeout borne le temps pendant lequel un point de contrôle TRUNCATE peut bloquer les
	// écritures en attendant la fin des lectures (10 s pour les requêtes ordinaires, voir Open).
	checkpointBusyTimeout = 250 * time.Millisecond
	// walForceBytes : au-delà, le délai court n'a pas suffi à recycler le WAL depuis longtemps ; on accepte alors
	// de bloquer les écritures jusqu'à 10 s plutôt que de le laisser grossir sans limite.
	walForceBytes = 1 << 30
	// walWarnBytes : en dessous, un point de contrôle incomplet est normal (une lecture est en cours).
	walWarnBytes = 128 << 20
)

// StartMaintenance garde la base et son WAL à une taille raisonnable.
//
// Le point de contrôle automatique de SQLite ne recycle le WAL que si, à un instant donné, aucune
// lecture n'est en cours. Des tableaux de bord rafraîchis toutes les quelques secondes sur un pool de
// 10 connexions ne laissent jamais ce créneau : le WAL grossit sans limite (16 Go constatés pour une
// base de 5 Go). TRUNCATE recopie le WAL dans la base puis le tronque.
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
	conn, err := db.Conn(ctx)
	if err != nil {
		log.Warn("sqlite: maintenance sans connexion", "err", err)
		return
	}
	defer conn.Close()

	// TRUNCATE prend le verrou d'écriture et attend la fin des lectures en cours : avec le délai
	// ordinaire de 10 s, chaque écriture (agrégation, battements des passerelles) restait bloquée
	// d'autant (« database is locked », « context deadline exceeded »). Un délai court rend la main :
	// si des lectures durent, la passe suivante réessaie.
	if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA busy_timeout = %d`, checkpointTimeout(lastWALPages.Load()).Milliseconds())); err != nil {
		log.Warn("sqlite: délai du point de contrôle non réglé", "err", err)
		return
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `PRAGMA busy_timeout = 10000`) //nolint:errcheck

	var busy, walPages, moved int
	if err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &walPages, &moved); err != nil {
		log.Warn("sqlite: point de contrôle WAL en échec", "err", err)
	} else if busy == 0 {
		lastWALPages.Store(0)
	} else {
		lastWALPages.Store(int64(walPages))
		lvl := slog.LevelDebug
		if int64(walPages)*4096 > walWarnBytes {
			lvl = slog.LevelWarn
		}
		log.Log(ctx, lvl, "sqlite: point de contrôle WAL incomplet (lecture en cours), nouvel essai à la prochaine passe",
			"wal_pages", walPages, "recopiées", moved)
	}

	// Sans effet, et inutile, tant que la base n'est pas en auto_vacuum incrémental (voir docs/sauvegardes.md).
	var mode int
	if conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode) == nil && mode == 2 {
		// PRAGMA n'accepte pas de paramètre lié : la valeur est une constante.
		if _, err := conn.ExecContext(ctx, fmt.Sprintf(`PRAGMA incremental_vacuum(%d)`, incrementalVacuumPages)); err != nil {
			log.Warn("sqlite: incremental_vacuum en échec", "err", err)
		}
	}
}
