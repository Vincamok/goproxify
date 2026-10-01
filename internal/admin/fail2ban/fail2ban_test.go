// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package fail2ban

import (
	"database/sql"
	"io"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func newTestEngine(t *testing.T) (*Engine, *sql.DB) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	e := New(d, slog.New(slog.NewTextHandler(io.Discard, nil)))
	if err := e.SaveConfig(Config{Enabled: true, WindowSec: 300, MaxErrors: 5}); err != nil {
		t.Fatal(err)
	}
	return e, d
}

func insertForbidden(t *testing.T, d *sql.DB, ip string, at time.Time, n int) {
	t.Helper()
	for i := 0; i < n; i++ {
		if _, err := d.Exec(`INSERT INTO logs (ts, component, status, ip) VALUES (?, 'edge', 403, ?)`,
			at.UTC().Format(time.RFC3339Nano), ip); err != nil {
			t.Fatal(err)
		}
	}
}

func activeBans(t *testing.T, d *sql.DB, ip string) int {
	t.Helper()
	var n int
	if err := d.QueryRow(`SELECT COUNT(*) FROM security_bans WHERE ip=?`, ip).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestScanOnlyCountsErrorsInsideTheWindow(t *testing.T) {
	e, d := newTestEngine(t)
	const ip = "203.0.113.60"
	insertForbidden(t, d, ip, time.Now().Add(-20*time.Minute), 10)
	e.scan()
	if activeBans(t, d, ip) != 0 {
		t.Fatal("des erreurs vieilles de 20 min ne comptent pas dans une fenêtre de 5 min")
	}
	insertForbidden(t, d, ip, time.Now().Add(-time.Minute), 5)
	e.scan()
	if activeBans(t, d, ip) != 1 {
		t.Fatal("5 erreurs dans la fenêtre doivent bannir")
	}
}

func TestScanDoesNotRebanRightAfterAnUnban(t *testing.T) {
	e, d := newTestEngine(t)
	const ip = "203.0.113.61"
	// 403 servis par le ban pendant la minute précédant le déban.
	insertForbidden(t, d, ip, time.Now().Add(-time.Minute), 20)
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, action, source) VALUES (?, 'unbanned', 'fail2ban')`, ip); err != nil {
		t.Fatal(err)
	}
	e.scan()
	if activeBans(t, d, ip) != 0 {
		t.Fatal("les erreurs antérieures au déban ne doivent pas rebannir")
	}
	insertForbidden(t, d, ip, time.Now().Add(2*time.Second), 5)
	e.scan()
	if activeBans(t, d, ip) != 1 {
		t.Fatal("de nouvelles erreurs après le déban doivent rebannir")
	}
}

func TestLastBanEndIsTheLatestUnbanOrExpiry(t *testing.T) {
	e, d := newTestEngine(t)
	const ip = "203.0.113.62"
	if !e.lastBanEnd(ip).IsZero() {
		t.Fatal("jamais banni : pas de fin de ban")
	}
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, action, created_at) VALUES (?, 'unbanned', datetime('now','-10 minutes'))`, ip); err != nil {
		t.Fatal(err)
	}
	expired := time.Now().Add(-30 * time.Second).UTC().Truncate(time.Second)
	future := time.Now().Add(time.Hour).UTC()
	for id, exp := range map[string]time.Time{"expire": expired, "actif": future} {
		if _, err := d.Exec(`INSERT INTO security_bans (id, ip, reason, source, expires_at) VALUES (?, ?, '', 'threat', ?)`,
			id, ip, exp.Format(time.RFC3339)); err != nil {
			t.Fatal(err)
		}
	}
	if got := e.lastBanEnd(ip); !got.Equal(expired) {
		t.Fatalf("fin du dernier ban : %v, attendu l'expiration %v (un ban encore actif n'est pas une fin)", got, expired)
	}
}

func allBans(t *testing.T, d *sql.DB) []string {
	t.Helper()
	rows, err := d.Query(`SELECT ip FROM security_bans ORDER BY ip`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var out []string
	for rows.Next() {
		var ip string
		if err := rows.Scan(&ip); err != nil {
			t.Fatal(err)
		}
		out = append(out, ip)
	}
	return out
}

func TestScanBanTarget(t *testing.T) {
	for _, tc := range []struct{ logged, want string }{
		{"203.0.113.70", "203.0.113.70"},
		{"203.0.113.71:51234", "203.0.113.71"},
		{"2a01:e0a:1:2::5", "2a01:e0a:1:2::/64"},
		{"[2a01:e0a:1:3::5]:443", "2a01:e0a:1:3::/64"},
	} {
		e, d := newTestEngine(t)
		insertForbidden(t, d, tc.logged, time.Now().Add(-time.Minute), 5)
		e.scan()
		if got := allBans(t, d); len(got) != 1 || got[0] != tc.want {
			t.Errorf("logs.ip=%q : bans %v, attendu [%s]", tc.logged, got, tc.want)
		}
	}
}

func TestScanIgnoresPseudonymizedIPs(t *testing.T) {
	e, d := newTestEngine(t)
	insertForbidden(t, d, "[pseudonymisé]", time.Now().Add(-time.Minute), 10)
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("une IP pseudonymisée ne peut pas être bannie : %v", got)
	}
}

func TestScanAggregatesIPv6By64(t *testing.T) {
	e, d := newTestEngine(t)
	at := time.Now().Add(-time.Minute)
	for _, ip := range []string{"2a01:e0a:1:2::1", "2a01:e0a:1:2::2", "2a01:e0a:1:2::3", "2a01:e0a:1:2:abcd::4"} {
		insertForbidden(t, d, ip, at, 1)
	}
	insertForbidden(t, d, "2a01:e0a:1:3::1", at, 1)
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("4 erreurs dans le /64 sous un seuil de 5 : bans %v", got)
	}
	insertForbidden(t, d, "2a01:e0a:1:2::5", at, 1)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "2a01:e0a:1:2::/64" {
		t.Fatalf("5 erreurs réparties sur le /64 : bans %v, attendu [2a01:e0a:1:2::/64]", got)
	}
}

func TestScanIPv6Whitelist(t *testing.T) {
	e, d := newTestEngine(t)
	if err := e.SaveConfig(Config{Enabled: true, WindowSec: 300, MaxErrors: 5, Whitelist: []string{"2a01:e0a:1:4::5"}}); err != nil {
		t.Fatal(err)
	}
	insertForbidden(t, d, "2a01:e0a:1:4::5", time.Now().Add(-time.Minute), 10)
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("une IPv6 en liste blanche ne doit pas être bannie : %v", got)
	}
	insertForbidden(t, d, "2a01:e0a:1:4::6", time.Now().Add(-time.Minute), 5)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "2a01:e0a:1:4::6" {
		t.Fatalf("voisine d'une IP exemptée : bans %v, attendu l'adresse seule, pas le /64", got)
	}
}

func TestScanDoesNotRebanIPv6PrefixRightAfterAnUnban(t *testing.T) {
	e, d := newTestEngine(t)
	insertForbidden(t, d, "2a01:e0a:1:2::5", time.Now().Add(-time.Minute), 20)
	if _, err := d.Exec(`INSERT INTO security_ban_history (ip, action, source) VALUES ('2a01:e0a:1:2::/64', 'unbanned', 'fail2ban')`); err != nil {
		t.Fatal(err)
	}
	e.scan()
	if got := allBans(t, d); len(got) != 0 {
		t.Fatalf("les erreurs antérieures au déban du /64 ne doivent pas rebannir : %v", got)
	}
	insertForbidden(t, d, "2a01:e0a:1:2::9", time.Now().Add(2*time.Second), 5)
	e.scan()
	if got := allBans(t, d); len(got) != 1 || got[0] != "2a01:e0a:1:2::/64" {
		t.Fatalf("de nouvelles erreurs après le déban doivent rebannir le /64 : %v", got)
	}
}

func TestScanRebansOnceThePreviousBanHasExpired(t *testing.T) {
	e, d := newTestEngine(t)
	expired := time.Now().Add(-time.Minute)
	for ip, exp := range map[string]string{
		"203.0.113.63": expired.UTC().Format(time.RFC3339),
		"203.0.113.64": expired.In(time.FixedZone("", 2*3600)).Format(time.RFC3339),
	} {
		if _, err := d.Exec(`INSERT INTO security_bans (id, ip, source, expires_at) VALUES (?, ?, 'fail2ban', ?)`,
			"ancien-"+ip, ip, exp); err != nil {
			t.Fatal(err)
		}
		insertForbidden(t, d, ip, time.Now(), 5)
	}
	e.scan()
	for _, ip := range []string{"203.0.113.63", "203.0.113.64"} {
		if activeBans(t, d, ip) != 2 {
			t.Errorf("%s : un ban expiré depuis 1 min ne compte plus comme « déjà banni », et les erreurs qui suivent son expiration comptent", ip)
		}
	}
}
