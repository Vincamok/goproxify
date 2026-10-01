// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package bansdb

import (
	"testing"
	"time"
)

func TestUnbanOnlyLiftsBansPostedBeforeIt(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const ip = "203.0.113.5"
	old := time.Now().Add(-2 * time.Hour).UTC().Format(sqlTime)
	for _, src := range []string{"fail2ban", "threat", "admin"} {
		if _, err := d.db.Exec(`INSERT INTO bans (id, ip, source, created_at) VALUES (?, ?, ?, ?)`, src+"-old", ip, src, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := d.UpsertBan("fail2ban-new", ip, "", "", "fail2ban", nil); err != nil {
		t.Fatal(err)
	}

	at := time.Now().Add(-time.Hour)
	if err := d.Unban(ip, at); err != nil {
		t.Fatal(err)
	}
	rows, err := d.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 || rows[0].ID != "fail2ban-new" {
		t.Fatalf("seul le ban posé après le déban doit rester, toutes sources confondues : %+v", rows)
	}
	if rows[0].CreatedAt.IsZero() {
		t.Fatal("created_at doit être relu (filtre des bans de pairs)")
	}

	// Un déban plus ancien ne recule pas la date retenue.
	if err := d.Unban(ip, at.Add(-time.Hour)); err != nil {
		t.Fatal(err)
	}
	unbans, err := d.Unbans()
	if err != nil {
		t.Fatal(err)
	}
	if got := unbans[ip]; !got.Equal(at.UTC().Truncate(time.Second)) {
		t.Fatalf("date de déban retenue : %v, attendu %v", got, at.UTC().Truncate(time.Second))
	}
}

func TestExpiredBanIsNeitherActiveNorKept(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	past, future := time.Now().Add(-time.Minute), time.Now().Add(time.Hour)
	for id, exp := range map[string]*time.Time{"expire": &past, "actif": &future, "permanent": nil} {
		if err := d.UpsertBan(id, "203.0.113.7", "", "", "fail2ban", exp); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := d.ActiveBans()
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		if r.ID == "expire" {
			t.Fatal("un ban expiré depuis 1 min n'est plus actif (et non jusqu'à minuit UTC)")
		}
	}
	if len(rows) != 2 {
		t.Fatalf("2 bans actifs attendus : %+v", rows)
	}
	if err := d.PurgeExpiredBans(); err != nil {
		t.Fatal(err)
	}
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM bans`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	if n != 2 {
		t.Fatalf("la purge supprime le ban expiré et lui seul : %d bans restants", n)
	}
}

func TestHistoryWindowsSeeTodaysEvents(t *testing.T) {
	d, err := Open(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	const ip = "203.0.113.8"
	if _, err := d.db.Exec(`INSERT INTO ban_history (ip, source, created_at) VALUES (?, 'threat', ?)`,
		ip, time.Now().Add(-time.Hour).UTC().Format(sqlTime)); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if err := d.RecordBanEvent(ip, "threat"); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 10; i++ {
		if err := d.RecordProxyEvent("a.example", i < 5); err != nil {
			t.Fatal(err)
		}
	}

	since := time.Now().Add(-5 * time.Minute)
	check := func(step string) {
		t.Helper()
		if n, err := d.RecentBanCount(since, "threat"); err != nil || n != 3 {
			t.Fatalf("%s : %d bans dans les 5 dernières minutes, attendu 3 (err %v)", step, n, err)
		}
		if got, n, err := d.RepeatBanIP(since, 3); err != nil || got != ip || n != 3 {
			t.Fatalf("%s : IP récidiviste %q (%d), attendu %s (3)", step, got, n, ip)
		}
		if rows, err := d.BanHistorySince(since); err != nil || len(rows) != 3 {
			t.Fatalf("%s : %d entrées d'historique, attendu 3 (err %v)", step, len(rows), err)
		}
		if rate, host, err := d.ProxyErrorRate(since, 10); err != nil || host != "a.example" || rate != 50 {
			t.Fatalf("%s : taux d'erreurs %v sur %q, attendu 50 sur a.example (err %v)", step, rate, host, err)
		}
	}
	check("avant purge")
	if err := d.PurgeBanHistory(since); err != nil {
		t.Fatal(err)
	}
	if err := d.PurgeProxyErrors(since); err != nil {
		t.Fatal(err)
	}
	check("après purge des entrées antérieures à la fenêtre")
	var n int
	if err := d.db.QueryRow(`SELECT COUNT(*) FROM ban_history`).Scan(&n); err != nil || n != 3 {
		t.Fatalf("seule l'entrée vieille d'1 h doit être purgée : %d restantes", n)
	}
}
