// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package gdpr_test

import (
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/gdpr"
)

func TestEdgeErasureQueueKeepsTheIPEncryptedAndDeduplicates(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	key, err := gdpr.EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	for _, ip := range []string{"203.0.113.42", "2001:DB8::1", "203.0.113.42", "2001:db8::1"} {
		if err := gdpr.QueueEdgeErasure(db, key, ip); err != nil {
			t.Fatal(err)
		}
	}
	var clear int
	db.QueryRow(`SELECT COUNT(*) FROM edge_erasure_queue WHERE ip_enc LIKE '%203.0.113%' OR lower(ip_enc) LIKE '%db8%'`).Scan(&clear) //nolint:errcheck
	if clear != 0 {
		t.Fatalf("%d ligne(s) gardent l'IP en clair", clear)
	}
	got, err := gdpr.PendingEdgeErasures(db, key)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "203.0.113.42,2001:db8::1" {
		t.Fatalf("en attente : %v", got)
	}

	if _, err := db.Exec(`UPDATE edge_erasure_queue SET created_at = datetime('now', '-91 days') WHERE id = 1`); err != nil {
		t.Fatal(err)
	}
	if err := gdpr.PurgeEdgeErasures(db, 90); err != nil {
		t.Fatal(err)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM edge_erasure_queue`).Scan(&n) //nolint:errcheck
	if n != 3 {
		t.Fatalf("%d lignes après purge, attendu 3", n)
	}
}
