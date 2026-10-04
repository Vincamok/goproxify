// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestGetTopTLSFingerprints(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	ins := func(ip, ja3, ja4 string, status int, threat string, trunc int) {
		t.Helper()
		if _, err := db.Exec(`INSERT INTO logs (ts, component, domain, method, path, status, ip, tls_ja3, tls_ja4, threat_signal, ip_truncated)
			VALUES (?, 'edge', 'a.test', 'GET', '/', ?, ?, ?, ?, ?, ?)`, now.Format(time.RFC3339), status, ip, ja3, ja4, threat, trunc); err != nil {
			t.Fatal(err)
		}
	}
	ins("198.51.100.1", "j3a", "t13d_scanner", 403, "rate", 0)
	ins("198.51.100.2", "j3a", "t13d_scanner", 404, "", 0)
	ins("198.51.100.2", "j3a", "t13d_scanner", 200, "", 0)
	ins("203.0.113.0", "j3a", "t13d_scanner", 200, "", 1)
	ins("192.0.2.9", "j3b", "t13d_browser", 200, "", 0)
	ins("192.0.2.9", "", "", 200, "", 0)

	out := GetTopTLSFingerprints(db, Params{From: now.Add(-time.Hour), To: now.Add(time.Hour)}, 10)
	if len(out) != 2 {
		t.Fatalf("%d empreintes, attendu 2 (les requêtes sans empreinte sont ignorées) : %+v", len(out), out)
	}
	s := out[0]
	if s.JA4 != "t13d_scanner" || s.Requests != 4 || s.Errors != 2 || s.Flagged != 1 {
		t.Fatalf("scanner : %+v", s)
	}
	if s.UniqueIPs != 2 {
		t.Fatalf("IP uniques = %d, attendu 2 (l'IP tronquée n'est pas un client)", s.UniqueIPs)
	}
	if got := GetTopTLSFingerprints(db, Params{From: now.Add(-time.Hour), To: now.Add(time.Hour), IP: "192.0.2.9"}, 10); len(got) != 1 || got[0].JA4 != "t13d_browser" {
		t.Fatalf("filtre IP : %+v", got)
	}
}
