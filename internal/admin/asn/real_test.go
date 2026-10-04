// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package asn

import (
	"net/netip"
	"os"
	"testing"
	"time"
)

// Vérification manuelle sur le vrai jeu de données : GPX_ASN_TEST_FILE=<ip2asn-combined.tsv.gz>.
func TestRealDataset(t *testing.T) {
	path := os.Getenv("GPX_ASN_TEST_FILE")
	if path == "" {
		t.Skip("GPX_ASN_TEST_FILE non défini")
	}
	f, err := os.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	start := time.Now()
	idx, err := ParseGzip(f)
	if err != nil {
		t.Fatal(err)
	}
	asns, ranges := idx.Len()
	t.Logf("chargé en %v : %d ASN, %d plages", time.Since(start), asns, ranges)
	for _, n := range []uint32{16276, 3215, 13335, 15169} {
		e, ok := idx.Get(n)
		if !ok {
			t.Errorf("AS%d absent", n)
			continue
		}
		ps, skipped := e.BanPrefixes()
		t.Logf("AS%d %s (%s) : %d plages annoncées, %.0f adresses IPv4, %d plages IPv6, %d CIDR à bannir, %d ignorée(s)", n, e.Name, e.Country, len(e.Ranges), e.V4Addresses(), e.V6Ranges(), len(ps), skipped)
	}
	if e, ok := idx.ByIP(netip.MustParseAddr("1.1.1.1")); !ok || e.ASN != 13335 {
		t.Errorf("1.1.1.1 : %v %v", e, ok)
	}
	if e, ok := idx.ByIP(netip.MustParseAddr("8.8.8.8")); !ok || e.ASN != 15169 {
		t.Errorf("8.8.8.8 : %v %v", e, ok)
	}
	t.Logf("recherche « ovh » : %d résultats", len(idx.Search("ovh", 20)))
}
