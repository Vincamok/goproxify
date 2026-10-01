// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package sqltime écrit les dates SQLite au format de CURRENT_TIMESTAMP, en UTC.
//
// SQLite compare les dates en texte : une colonne comparée à CURRENT_TIMESTAMP ou à
// datetime('now', …) ('2026-09-29 10:00:00') doit être écrite dans ce format. Une date
// RFC3339 ('2026-09-29T10:00:00Z') passe pour plus tardive toute la journée ('T' > ' '),
// et un time.Time lié tel quel est écrit par le pilote via t.String()
// ('2026-09-29 12:00:00 +0200 CEST m=+0.1') : heure locale, que datetime() et julianday()
// ne savent pas lire.
package sqltime

import (
	"database/sql"
	"fmt"
	"strings"
	"time"
)

// Layout est le format de CURRENT_TIMESTAMP.
const Layout = "2006-01-02 15:04:05"

// Format renvoie t en UTC au format de CURRENT_TIMESTAMP.
func Format(t time.Time) string {
	return t.UTC().Format(Layout)
}

// Nullable renvoie nil (NULL) pour t nil, Format(*t) sinon.
func Nullable(t *time.Time) any {
	if t == nil {
		return nil
	}
	return Format(*t)
}

// Parse lit une date texte : RFC3339, format de CURRENT_TIMESTAMP (UTC) ou t.String().
func Parse(s string) (time.Time, error) {
	s = strings.TrimSpace(s)
	for _, l := range []string{time.RFC3339Nano, "2006-01-02 15:04:05.999999999"} {
		if t, err := time.Parse(l, s); err == nil {
			return t, nil
		}
	}
	// t.String() : « 2006-01-02 15:04:05.999999999 -0700 MST m=+0.1 ». L'abréviation vaut « -0500 »
	// pour un décalage hors du fuseau local, que time.Parse (et donc le pilote) ne sait pas relire.
	if f := strings.Fields(s); len(f) >= 3 {
		if t, err := time.Parse("2006-01-02 15:04:05.999999999 -0700", strings.Join(f[:3], " ")); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("date illisible : %q", s)
}

// Text ramène une date texte au format de CURRENT_TIMESTAMP ; une valeur illisible est renvoyée telle quelle.
func Text(s string) string {
	if t, err := Parse(s); err == nil {
		return Format(t)
	}
	return s
}

// Normalize réécrit au format de CURRENT_TIMESTAMP les dates de table.col écrites autrement
// (RFC3339, décalage horaire, t.String()). Les lignes déjà au bon format ne sont pas relues ;
// une valeur illisible est laissée telle quelle.
func Normalize(db *sql.DB, table, col string) error {
	rows, err := db.Query(`SELECT rowid, ` + col + ` FROM ` + table +
		` WHERE ` + col + ` IS NOT NULL AND datetime(` + col + `) IS NOT ` + col)
	if err != nil {
		return err
	}
	fixes := map[int64]string{}
	for rows.Next() {
		var id int64
		var v any
		if err := rows.Scan(&id, &v); err != nil {
			rows.Close()
			return err
		}
		// Le pilote convertit déjà en time.Time les colonnes DATETIME qu'il sait lire.
		switch v := v.(type) {
		case time.Time:
			fixes[id] = Format(v)
		case string:
			if t, err := Parse(v); err == nil {
				fixes[id] = Format(t)
			}
		}
	}
	rows.Close()
	if err := rows.Err(); err != nil {
		return err
	}
	for id, v := range fixes {
		if _, err := db.Exec(`UPDATE `+table+` SET `+col+`=? WHERE rowid=?`, v, id); err != nil {
			return err
		}
	}
	return nil
}
