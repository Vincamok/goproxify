// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestPurgeRetainedDropsEntriesPastTheirRetention(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for msg, until := range map[string]time.Time{"echu": time.Now().Add(-time.Minute), "conserve": time.Now().Add(time.Hour)} {
		if _, err := db.Exec(`INSERT INTO logs (ts, message, retained_until) VALUES (?, ?, ?)`,
			time.Now().UTC().Format(time.RFC3339Nano), msg, until.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	New(db).purgeRetained()
	var left []string
	rows, err := db.Query(`SELECT message FROM logs`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	for rows.Next() {
		var m string
		if err := rows.Scan(&m); err != nil {
			t.Fatal(err)
		}
		left = append(left, m)
	}
	if len(left) != 1 || left[0] != "conserve" {
		t.Fatalf("entrées restantes : %v, attendu [conserve] (rétention échue depuis 1 min = purgée, pas à minuit UTC)", left)
	}
}
