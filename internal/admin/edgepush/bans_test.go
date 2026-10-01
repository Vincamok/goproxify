// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgepush

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Formats d'expires_at qui coexistent dans security_bans.
var banExpiryFormats = map[string]func(time.Time) string{
	"rfc3339": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },               // passerelles, Fail2Ban, CrowdSec
	"iso-ms":  func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }, // UI (toISOString)
	"offset":  func(t time.Time) string { return t.In(time.FixedZone("", 2*3600)).Format(time.RFC3339) },
	"sqlite":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") },
}

func TestActiveBansSkipsBansExpiredAMinuteAgo(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	want := map[string]bool{"permanent": true}
	if _, err := db.Exec(`INSERT INTO security_bans (id, ip) VALUES ('permanent', '203.0.113.1')`); err != nil {
		t.Fatal(err)
	}
	for name, format := range banExpiryFormats {
		for suffix, at := range map[string]time.Time{"-expire": time.Now().Add(-time.Minute), "-actif": time.Now().Add(time.Hour)} {
			if _, err := db.Exec(`INSERT INTO security_bans (id, ip, expires_at) VALUES (?, '203.0.113.2', ?)`,
				name+suffix, format(at)); err != nil {
				t.Fatal(err)
			}
		}
		want[name+"-actif"] = true
	}

	list, err := New(db, slog.Default()).activeBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]bool{}
	for _, b := range list {
		got[b["id"].(string)] = true
	}
	if len(got) != len(want) {
		t.Fatalf("bans poussés aux passerelles : %v, attendu %v (un ban expiré depuis 1 min ne l'est plus, quel que soit son format)", got, want)
	}
	for id := range want {
		if !got[id] {
			t.Errorf("ban actif %s manquant", id)
		}
	}
}
