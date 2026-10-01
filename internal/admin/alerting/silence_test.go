// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package alerting

import (
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestSilenceStartedTodayIsApplied(t *testing.T) {
	path := filepath.Join(t.TempDir(), "t.db")
	d, err := db.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	// Silence importé avant le correctif : dates RFC3339, commencé il y a 1 min (le même jour UTC,
	// sauf à minuit) — 'T' > ' ', il ne démarrait qu'à minuit UTC.
	starts := time.Now().Add(-time.Minute).UTC()
	if _, err := d.Exec(`INSERT INTO automation_silences (id, name, rule_ids, starts_at, ends_at) VALUES ('s1', 'maintenance', '["r1"]', ?, ?)`,
		starts.Format(time.RFC3339), starts.Add(time.Hour).Format(time.RFC3339)); err != nil {
		t.Fatal(err)
	}
	d.Close()

	d, err = db.Open(path) // le démarrage ramène les dates au format de CURRENT_TIMESTAMP
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e := New(d, slog.Default())
	t.Cleanup(e.Stop)
	if !e.isSilenced("r1") {
		t.Error("r1 est couverte par un silence commencé il y a 1 min")
	}
	if e.isSilenced("r2") {
		t.Error("r2 n'est pas dans la portée du silence")
	}
}
