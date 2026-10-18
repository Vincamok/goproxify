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

func TestPurgeRetainedDropsOldIPTraces(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	old := time.Now().UTC().AddDate(0, 0, -DefaultRetentionBanDays-1).Format(time.RFC3339)
	recent := time.Now().UTC().AddDate(0, 0, -1).Format(time.RFC3339)
	future := time.Now().UTC().AddDate(0, 0, 1).Format(time.RFC3339)
	for _, q := range []string{
		`INSERT INTO security_ban_history (ip, action, created_at) VALUES ('198.51.100.1', 'banned', datetime('now', '-366 days'))`,
		`INSERT INTO security_ban_history (ip, action, created_at) VALUES ('198.51.100.2', 'banned', datetime('now', '-10 days'))`,
		`INSERT INTO security_bans (id, ip, expires_at) VALUES ('old', '198.51.100.1', '` + old + `')`,
		`INSERT INTO security_bans (id, ip, expires_at) VALUES ('recent', '198.51.100.2', '` + recent + `')`,
		`INSERT INTO security_bans (id, ip, expires_at) VALUES ('active', '198.51.100.3', '` + future + `')`,
		`INSERT INTO security_bans (id, ip) VALUES ('permanent', '198.51.100.4')`,
		`INSERT INTO geoip_cache (ip, country_code, cached_at) VALUES ('198.51.100.1', 'FR', datetime('now', '-366 days'))`,
		`INSERT INTO geoip_cache (ip, country_code, cached_at) VALUES ('198.51.100.2', 'FR', datetime('now', '-10 days'))`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	New(db).purgeRetained()

	ips := func(q string) string {
		rows, err := db.Query(q)
		if err != nil {
			t.Fatal(err)
		}
		defer rows.Close()
		var out string
		for rows.Next() {
			var v string
			if err := rows.Scan(&v); err != nil {
				t.Fatal(err)
			}
			out += v + ";"
		}
		return out
	}
	if got := ips(`SELECT ip FROM security_ban_history ORDER BY ip`); got != "198.51.100.2;" {
		t.Errorf("security_ban_history = %q, attendu seul le .2 (récent)", got)
	}
	if got := ips(`SELECT id FROM security_bans ORDER BY id`); got != "active;permanent;recent;" {
		t.Errorf("security_bans = %q, seul le ban expiré depuis plus de la rétention doit partir", got)
	}
	if got := ips(`SELECT ip FROM geoip_cache ORDER BY ip`); got != "198.51.100.2;" {
		t.Errorf("geoip_cache = %q, attendu seul le .2 (récent)", got)
	}
}

func TestEraseIPCoversBansHistoryAndGeoCache(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO security_bans (id, ip) VALUES ('b1', '2001:db8::1')`,
		`INSERT INTO security_bans (id, ip) VALUES ('b2', '2001:db8::2')`,
		`INSERT INTO security_ban_history (ip, action) VALUES ('2001:db8::1', 'banned')`,
		`INSERT INTO security_ban_history (ip, action) VALUES ('2001:db8::2', 'banned')`,
		`INSERT INTO geoip_cache (ip, country_code) VALUES ('2001:db8::1', 'FR')`,
		`INSERT INTO geoip_cache (ip, country_code) VALUES ('2001:db8::2', 'FR')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	// Notation non canonique : l'IP est trouvée quelle que soit son écriture.
	res, err := New(db).EraseIP("2001:0DB8:0:0:0:0:0:1")
	if err != nil {
		t.Fatal(err)
	}
	if res.Bans != 1 || res.BanHistory != 1 || res.GeoCache != 1 {
		t.Fatalf("effacement = %+v, attendu 1 ban, 1 événement, 1 entrée GeoIP", res)
	}
	var left int
	db.QueryRow(`SELECT (SELECT COUNT(*) FROM security_bans) + (SELECT COUNT(*) FROM security_ban_history) + (SELECT COUNT(*) FROM geoip_cache)`).Scan(&left) //nolint:errcheck
	if left != 3 {
		t.Fatalf("%d lignes restantes, attendu 3 (celles de 2001:db8::2)", left)
	}
}
