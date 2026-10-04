// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestTLSFingerprintStoredAndFiltered(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatalf("ouverture DB : %v", err)
	}
	defer db.Close()
	s := New(db)

	s.Write(Entry{Status: 200, Message: "curl", TLSJA3: "aaa", TLSJA4: "t13d1516h2_x_y", RequestID: "r1"})
	s.Write(Entry{Status: 200, Message: "curl 2", TLSJA3: "aaa", TLSJA4: "t13d1516h2_x_y"})
	s.Write(Entry{Status: 200, Message: "navigateur", TLSJA3: "bbb", TLSJA4: "t13d1517h2_z_w"})
	s.Write(Entry{Status: 200, Message: "http clair"})

	byJA4, _, err := s.Search(SearchParams{TLSJA4: "t13d1516h2_x_y"})
	if err != nil {
		t.Fatal(err)
	}
	if len(byJA4) != 2 {
		t.Fatalf("filtre JA4 : %d entrées, attendu 2", len(byJA4))
	}
	if byJA4[0].TLSJA3 != "aaa" || byJA4[0].TLSJA4 != "t13d1516h2_x_y" {
		t.Fatalf("empreintes non relues : %+v", byJA4[0])
	}

	byJA3, _, _ := s.Search(SearchParams{TLSJA3: "bbb"})
	if len(byJA3) != 1 || byJA3[0].Message != "navigateur" {
		t.Fatalf("filtre JA3 : %+v", byJA3)
	}

	corr := s.CorrelateByRequestID("r1")
	if len(corr) != 1 || corr[0].TLSJA4 != "t13d1516h2_x_y" {
		t.Fatalf("corrélation sans empreinte : %+v", corr)
	}

	facets, err := s.Facets(SearchParams{}, []string{"tls_ja4"})
	if err != nil {
		t.Fatal(err)
	}
	if got := facets["tls_ja4"]; len(got) != 2 || got[0].Value != "t13d1516h2_x_y" || got[0].Count != 2 {
		t.Fatalf("facettes JA4 : %+v", got)
	}
}
