// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"context"
	"database/sql"
	"log/slog"
	"time"
)

const (
	aggInterval = 10 * time.Second
	// aggChunk borne le nombre d'ids lus par transaction : le rattrapage de l'historique se fait par
	// tranches, sans bloquer longtemps les écritures de logs.
	aggChunk = 100000
	// aggPause laisse respirer le disque entre deux tranches pendant le rattrapage.
	aggPause = 200 * time.Millisecond
	// DefaultRetentionAggDays : les agrégats ne contiennent aucune donnée personnelle (ni IP, ni chemin),
	// ils survivent donc aux lignes brutes.
	DefaultRetentionAggDays = 400
)

// aggregate agrège dans logs_minute les accès HTTP (status > 0) d'id supérieur au repère, par
// tranches, puis avance le repère dans la même transaction : un arrêt brutal ne compte jamais une
// ligne deux fois. Retourne le nombre de tranches traitées et si l'historique est rattrapé.
func aggregate(ctx context.Context, db *sql.DB, maxChunks int) (chunks int, caughtUp bool, err error) {
	var maxID int64
	if err = db.QueryRowContext(ctx, `SELECT COALESCE(MAX(id), 0) FROM logs`).Scan(&maxID); err != nil {
		return 0, false, err
	}
	for chunks < maxChunks {
		var last int64
		if err = db.QueryRowContext(ctx, `SELECT COALESCE((SELECT v FROM logs_minute_state WHERE k='last_id'), 0)`).Scan(&last); err != nil {
			return chunks, false, err
		}
		if last >= maxID {
			return chunks, true, setReady(ctx, db)
		}
		upTo := min(last+aggChunk, maxID)
		tx, err := db.BeginTx(ctx, nil)
		if err != nil {
			return chunks, false, err
		}
		if _, err = tx.ExecContext(ctx,
			`INSERT INTO logs_minute (minute, node_name, domain, status, requests, bytes, latency_ms_sum, bots)
			 SELECT substr(ts, 1, 16), node_name, domain, status, COUNT(*), COALESCE(SUM(bytes), 0), COALESCE(SUM(latency_ms), 0),
			        SUM(CASE WHEN lower(component) LIKE '%bot%' OR lower(message) LIKE '%bot%' THEN 1 ELSE 0 END)
			 FROM logs WHERE id > ? AND id <= ? AND status > 0
			 GROUP BY 1, 2, 3, 4
			 ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET
			   requests = requests + excluded.requests, bytes = bytes + excluded.bytes,
			   latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum, bots = bots + excluded.bots`,
			last, upTo); err == nil {
			_, err = tx.ExecContext(ctx, `INSERT INTO logs_minute_state (k, v) VALUES ('last_id', ?)
				ON CONFLICT (k) DO UPDATE SET v = excluded.v`, upTo)
		}
		if err != nil {
			tx.Rollback() //nolint:errcheck
			return chunks, false, err
		}
		if err = tx.Commit(); err != nil {
			return chunks, false, err
		}
		chunks++
		if upTo < maxID {
			select {
			case <-ctx.Done():
				return chunks, false, ctx.Err()
			case <-time.After(aggPause):
			}
		}
	}
	return chunks, false, nil
}

func setReady(ctx context.Context, db *sql.DB) error {
	_, err := db.ExecContext(ctx, `INSERT INTO logs_minute_state (k, v) VALUES ('ready', 1)
		ON CONFLICT (k) DO UPDATE SET v = 1`)
	return err
}

// StartAggregator alimente logs_minute en tâche de fond. Les lecteurs ne s'appuient sur les agrégats
// qu'une fois l'historique rattrapé (indicateur « ready ») : avant, ils lisent les lignes brutes.
func (s *Store) StartAggregator(ctx context.Context, log *slog.Logger) {
	go func() {
		t := time.NewTicker(aggInterval)
		defer t.Stop()
		for {
			if _, _, err := aggregate(ctx, s.db, 1<<30); err != nil && ctx.Err() == nil {
				log.Warn("logs: agrégation par minute en échec (nouvel essai au prochain cycle)", "err", err)
			}
			select {
			case <-ctx.Done():
				return
			case <-t.C:
			}
		}
	}()
}

// purgeAggregates supprime les agrégats plus vieux que la durée de conservation.
func (s *Store) purgeAggregates(days int) {
	cut := time.Now().UTC().AddDate(0, 0, -days).Format("2006-01-02T15:04")
	s.db.Exec(`DELETE FROM logs_minute WHERE minute < ?`, cut) //nolint:errcheck
}

// AggregateNow rattrape tout ce qui reste à agréger, sans attendre le prochain cycle.
func AggregateNow(ctx context.Context, db *sql.DB) error {
	_, _, err := aggregate(ctx, db, 1<<30)
	return err
}
