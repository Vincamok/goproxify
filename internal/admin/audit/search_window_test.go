// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestSearchWindowMatchesEntriesOfTheDay(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	l := &Logger{db: d, retentionDays: 90}
	if err := db.WriteAudit(d, "alice", "proxy.update", "proxy:p1", ""); err != nil { // created_at = CURRENT_TIMESTAMP
		t.Fatal(err)
	}

	// Bornes reçues de l'API avec le décalage du navigateur (time.Parse garde le décalage).
	now := time.Now().In(time.FixedZone("", 2*3600))
	count := func(p SearchParams) int {
		t.Helper()
		_, n, err := l.Search(p)
		if err != nil {
			t.Fatal(err)
		}
		return n
	}
	if n := count(SearchParams{From: now.Add(-time.Minute)}); n != 1 {
		t.Errorf("depuis 1 min : %d entrée, attendu 1", n)
	}
	if n := count(SearchParams{From: now.Add(-time.Hour), To: now.Add(-30 * time.Minute)}); n != 0 {
		t.Errorf("de -1 h à -30 min : %d entrée, attendu 0", n)
	}
	if pts, err := l.Histogram(SearchParams{From: now.Add(-time.Minute)}, "minute"); err != nil || len(pts) != 1 {
		t.Errorf("histogramme depuis 1 min : %+v (err %v), attendu 1 tranche", pts, err)
	}
}
