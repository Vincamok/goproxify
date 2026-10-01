// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestOverviewActiveBansIgnoresBansExpiredAMinuteAgo(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for id, exp := range map[string]time.Time{"expire": time.Now().Add(-time.Minute), "actif": time.Now().Add(time.Hour)} {
		if _, err := d.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES (?, '203.0.113.22', 'threat', ?)`,
			id, exp.UTC().Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	if n := New(d).GetOverview(nil).ActiveBans; n != 1 {
		t.Errorf("%d bans actifs, attendu 1 (un ban expiré depuis 1 min ne l'est plus)", n)
	}
}
