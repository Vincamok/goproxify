// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package sqltime

import (
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	_ "modernc.org/sqlite"
)

func TestNormalizeMakesLegacyDatesComparable(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE t (id TEXT PRIMARY KEY, at DATETIME)`); err != nil {
		t.Fatal(err)
	}
	past := time.Now().Add(-time.Minute).Truncate(time.Second)
	paris := time.FixedZone("CEST", 2*3600)
	values := map[string]any{
		"stdlib-local": past.In(paris),                       // time.Time lié tel quel → t.String()
		"stdlib-utc":   past.UTC(),                           // idem, en UTC
		"stdlib-anon":  past.In(time.FixedZone("", -5*3600)), // « -0500 -0500 » : illisible pour le pilote
		"rfc3339":      past.UTC().Format(time.RFC3339),      // import, MCP
		"rfc3339-off":  past.In(paris).Format(time.RFC3339Nano),
		"sqlite":       Format(past),
		"garbage":      "bientôt",
	}
	for id, v := range values {
		if _, err := db.Exec(`INSERT INTO t (id, at) VALUES (?, ?)`, id, v); err != nil {
			t.Fatal(err)
		}
	}
	var nulls int
	db.QueryRow(`SELECT COUNT(*) FROM t WHERE julianday(at) IS NULL`).Scan(&nulls) //nolint:errcheck
	if nulls != 4 {
		t.Fatalf("julianday() doit être NULL pour t.String() et « bientôt » avant normalisation : %d", nulls)
	}

	if err := Normalize(db, "t", "at"); err != nil {
		t.Fatal(err)
	}
	if err := Normalize(db, "t", "at"); err != nil {
		t.Fatal("idempotent :", err)
	}
	rows, err := db.Query(`SELECT id, CAST(at AS TEXT), at <= CURRENT_TIMESTAMP FROM t`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var id, raw string
		var expired bool
		if err := rows.Scan(&id, &raw, &expired); err != nil {
			t.Fatal(err)
		}
		if id == "garbage" {
			if raw != "bientôt" {
				t.Errorf("une valeur illisible reste telle quelle : %q", raw)
			}
			continue
		}
		if raw != Format(past) {
			t.Errorf("%s : %q, attendu %q", id, raw, Format(past))
		}
		if !expired {
			t.Errorf("%s : passée d'une minute, doit être <= CURRENT_TIMESTAMP", id)
		}
	}
}

func TestParse(t *testing.T) {
	want := time.Date(2026, 10, 1, 8, 30, 0, 0, time.UTC)
	for _, s := range []string{
		"2026-10-01T08:30:00Z",
		"2026-10-01T10:30:00+02:00",
		"2026-10-01T08:30:00.000Z",
		"2026-10-01 08:30:00",
		"2026-10-01 10:30:00 +0200 CEST",
		"2026-10-01 03:30:00.5 -0500 -0500 m=+12.000000001",
	} {
		got, err := Parse(s)
		if err != nil {
			t.Errorf("%q : %v", s, err)
			continue
		}
		if !got.Truncate(time.Second).Equal(want) {
			t.Errorf("%q : %v, attendu %v", s, got, want)
		}
	}
	if _, err := Parse("demain"); err == nil {
		t.Error("« demain » n'est pas une date")
	}
}
