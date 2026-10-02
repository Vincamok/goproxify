// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/gdpr"
)

func newRGPDStore(t *testing.T) (*Store, *sql.DB, []byte) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	key, err := gdpr.EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	s := New(db)
	s.SetGDPRKey(key)
	return s, db, key
}

func countLogs(t *testing.T, db *sql.DB) int {
	t.Helper()
	var n int
	if err := db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestDeleteByIPErasesPseudonymizedEntries(t *testing.T) {
	s, db, _ := newRGPDStore(t)
	s.SetPseudonymize(true)
	s.Write(Entry{Status: 200, IP: "203.0.113.0", RealIP: "203.0.113.42"})
	s.Write(Entry{Status: 404, IP: "2001:db8::", RealIP: "2001:db8::1"})
	s.Write(Entry{Status: 200, IP: "203.0.113.0", RealIP: "203.0.113.43"})
	s.SetPseudonymize(false)
	s.Write(Entry{Status: 200, IP: "203.0.113.42"})

	n, err := s.DeleteByIP("203.0.113.42")
	if err != nil || n != 2 {
		t.Fatalf("DeleteByIP(203.0.113.42) = %d, %v ; attendu 2 (pseudonymisée + en clair)", n, err)
	}
	// Écriture non canonique de la même IPv6.
	if n, _ := s.DeleteByIP("2001:0db8:0:0:0:0:0:0001"); n != 1 {
		t.Fatalf("DeleteByIP(IPv6 non canonique) = %d, attendu 1", n)
	}
	if got := countLogs(t, db); got != 1 {
		t.Fatalf("%d entrées restantes, attendu 1 (203.0.113.43)", got)
	}
}

func TestBackfillIPIndex(t *testing.T) {
	s, db, key := newRGPDStore(t)
	// Entrées pseudonymisées écrites avant l'existence de ip_hmac.
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		enc, err := gdpr.Encrypt(key, ip)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := db.Exec(`INSERT INTO logs (ts, level, component, status, ip, ip_enc) VALUES ('2026-09-21T10:00:00Z', 'info', 'edge', 200, ?, ?)`, PseudonymizedIP, enc); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO logs (ts, level, component, status, ip, ip_enc) VALUES ('2026-09-21T10:00:00Z', 'info', 'edge', 200, ?, 'illisible')`, PseudonymizedIP); err != nil {
		t.Fatal(err)
	}

	n, err := s.BackfillIPIndex(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("BackfillIPIndex = %d, %v ; attendu 2 (l'entrée illisible est sautée)", n, err)
	}
	if n, _ := s.BackfillIPIndex(context.Background()); n != 0 {
		t.Fatalf("second passage : %d entrées, attendu 0", n)
	}
	if n, _ := s.DeleteByIP("198.51.100.2"); n != 1 {
		t.Fatalf("DeleteByIP après rattrapage = %d, attendu 1", n)
	}
}

// L'interface masque Bannir et l'analyse d'IP d'après ip_truncated : le marqueur doit sortir de
// GET /logs (pagination par page comme par curseur) et du flux SSE, et rester absent sinon.
func TestIPTruncatedExposedInSearchAndStream(t *testing.T) {
	s, _, _ := newRGPDStore(t)
	_, ch, cancel := s.Subscribe()
	defer cancel()
	s.Write(Entry{Component: "edge", Status: 200, IP: "203.0.113.0", IPTruncated: true})
	s.Write(Entry{Component: "edge", Status: 200, IP: "2a01:e0a:1::", IPTruncated: true})
	s.Write(Entry{Component: "edge", Status: 200, IP: "198.51.100.7"})

	for _, marker := range []string{`"ip_truncated":true`, `"ip_truncated":true`, ""} {
		b, _ := json.Marshal(<-ch)
		if got := strings.Contains(string(b), "ip_truncated"); got != (marker != "") || !strings.Contains(string(b), marker) {
			t.Errorf("SSE %s : attendu %q", b, marker)
		}
	}

	want := map[string]bool{"203.0.113.0": true, "2a01:e0a:1::": true, "198.51.100.7": false}
	for name, p := range map[string]SearchParams{"offset": {}, "keyset": {BeforeID: 1 << 40}} {
		entries, _, err := s.Search(p)
		if err != nil || len(entries) != 3 {
			t.Fatalf("Search %s = %d entrées, %v ; attendu 3", name, len(entries), err)
		}
		for _, e := range entries {
			if e.IPTruncated != want[e.IP] {
				t.Errorf("Search %s : %s IPTruncated = %v, attendu %v", name, e.IP, e.IPTruncated, want[e.IP])
			}
		}
	}
}

func TestIPReferenceHidesTheIP(t *testing.T) {
	s, _, key := newRGPDStore(t)
	if ref := s.IPReference("203.0.113.42"); ref != "hmac:"+gdpr.IPIndex(key, "203.0.113.42") {
		t.Fatalf("IPReference avec clé = %q", ref)
	}
	s.SetGDPRKey(nil)
	for ip, want := range map[string]string{"203.0.113.42": "203.0.113.0", "2001:db8:1:2::1": "2001:db8:1::"} {
		if ref := s.IPReference(ip); ref != want || strings.Contains(ref, "42") {
			t.Errorf("IPReference(%s) sans clé = %q, attendu %q", ip, ref, want)
		}
	}
}
