// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/security"
)

func newInternalBatchServer(t *testing.T) *Server {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "batch.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &Server{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func TestInternalBans_OnlyValidUnprotectedTargetsAreStored(t *testing.T) {
	s := newInternalBatchServer(t)
	target, err := security.ParseBanTarget("198.51.100.7")
	if err != nil {
		t.Fatal(err)
	}
	if _, _, _, err := security.AddWhitelist(s.db, target, "poste d'admin", "test"); err != nil {
		t.Fatal(err)
	}

	body := `[
		{"ip":"203.0.113.9","reason":"scan","source":"sentinel"},
		{"ip":"198.51.100.7","reason":"protégée par la liste blanche"},
		{"ip":"pas-une-ip"},
		{"ip":"10.0.0.0/8","reason":"trop large"},
		{"ip":"192.0.2.1","expires_at":"demain"},
		{"ip":""}
	]`
	rr := httptest.NewRecorder()
	s.handleInternalBans(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/security/bans", strings.NewReader(body)))
	if rr.Code != http.StatusAccepted {
		t.Fatalf("status = %d", rr.Code)
	}
	rows, err := s.db.Query(`SELECT ip FROM security_bans ORDER BY ip`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var got []string
	for rows.Next() {
		var ip string
		rows.Scan(&ip)
		got = append(got, ip)
	}
	if len(got) != 1 || got[0] != "203.0.113.9" {
		t.Fatalf("bans enregistrés = %v, attendu seulement 203.0.113.9", got)
	}
}

func TestInternalBatches_AreBounded(t *testing.T) {
	s := newInternalBatchServer(t)
	var bans strings.Builder
	bans.WriteString("[")
	for i := 0; i <= maxInternalBans; i++ {
		if i > 0 {
			bans.WriteString(",")
		}
		fmt.Fprintf(&bans, `{"ip":"203.0.%d.%d"}`, i/250, i%250+1)
	}
	bans.WriteString("]")
	rr := httptest.NewRecorder()
	s.handleInternalBans(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/security/bans", strings.NewReader(bans.String())))
	if rr.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("lot de bans trop gros : %d, attendu 413", rr.Code)
	}
	var n int
	s.db.QueryRow(`SELECT COUNT(*) FROM security_bans`).Scan(&n)
	if n != 0 {
		t.Fatalf("%d bans enregistrés malgré le refus", n)
	}

	if got := clip(strings.Repeat("é", 3000), maxInternalString); len(got) > maxInternalString || !strings.HasSuffix(got, "é") {
		t.Fatalf("troncature invalide : %d octets", len(got))
	}
}
