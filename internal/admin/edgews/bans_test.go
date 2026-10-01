// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestLoadActiveBansSkipsBansExpiredAMinuteAgo(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Formats d'expires_at qui coexistent dans security_bans.
	formats := map[string]func(time.Time) string{
		"rfc3339": func(t time.Time) string { return t.UTC().Format(time.RFC3339) },               // passerelles, Fail2Ban, CrowdSec
		"iso-ms":  func(t time.Time) string { return t.UTC().Format("2006-01-02T15:04:05.000Z") }, // UI (toISOString)
		"offset":  func(t time.Time) string { return t.In(time.FixedZone("", 2*3600)).Format(time.RFC3339) },
		"sqlite":  func(t time.Time) string { return t.UTC().Format("2006-01-02 15:04:05") },
	}
	for name, format := range formats {
		for suffix, at := range map[string]time.Time{"-expire": time.Now().Add(-time.Minute), "-actif": time.Now().Add(time.Hour)} {
			if _, err := db.Exec(`INSERT INTO security_bans (id, ip, expires_at) VALUES (?, '203.0.113.3', ?)`,
				name+suffix, format(at)); err != nil {
				t.Fatal(err)
			}
		}
	}

	list, err := NewManager("", db, slog.Default()).loadActiveBans(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(list) != len(formats) {
		t.Fatalf("%d bans renvoyés à la connexion d'une passerelle, attendu %d (un ban expiré depuis 1 min ne l'est plus) : %+v",
			len(list), len(formats), list)
	}
	for _, b := range list {
		if b.ExpiresAt == nil || !b.ExpiresAt.After(time.Now()) {
			t.Errorf("%s : expiration %v, attendu dans le futur (sinon la passerelle l'appliquerait comme permanent)", b.ID, b.ExpiresAt)
		}
	}
}
