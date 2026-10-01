// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestBannedIPsIgnoreBansExpiredAMinuteAgo(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for ip, exp := range map[string]time.Time{"203.0.113.20": time.Now().Add(-time.Minute), "203.0.113.21": time.Now().Add(time.Hour)} {
		if _, err := d.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES (?, ?, 'threat', ?)`,
			ip, ip, exp.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	if set := activeBannedIPSet(d); len(set) != 1 || !set["203.0.113.21"] {
		t.Errorf("IP bannies actives : %v, attendu la seule IP au ban non expiré", set)
	}
	n := int64(0)
	for _, c := range geoBannedIPs(d) {
		n += c
	}
	if n != 1 {
		t.Errorf("IP bannies actives par pays : %d, attendu 1", n)
	}
}
