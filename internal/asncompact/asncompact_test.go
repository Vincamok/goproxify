// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package asncompact

import (
	"bytes"
	"compress/gzip"
	"net/netip"
	"testing"
)

func ra(s, e string, asn uint32) Range {
	return Range{Start: netip.MustParseAddr(s), End: netip.MustParseAddr(e), ASN: asn}
}

func TestRoundTripAndLookup(t *testing.T) {
	data, version, err := Encode([]Range{
		ra("198.51.100.0", "198.51.100.255", 64500),
		ra("1.0.0.0", "1.0.0.255", 13335),
		ra("203.0.113.0", "203.0.113.255", 64501),
		ra("2001:db8::", "2001:db8:ffff:ffff:ffff:ffff:ffff:ffff", 64502),
		ra("2606:4700::", "2606:4700:ffff:ffff:ffff:ffff:ffff:ffff", 13335),
		ra("10.0.0.0", "9.0.0.0", 1),    // inversée : écartée
		ra("10.0.0.0", "10.0.0.255", 0), // ASN 0 : non annoncée
	})
	if err != nil {
		t.Fatal(err)
	}
	db, err := Decode(data)
	if err != nil {
		t.Fatal(err)
	}
	if db.Version() != version || len(version) != versionLen {
		t.Fatalf("version %q / %q", db.Version(), version)
	}
	if v4, v6 := db.Len(); v4 != 3 || v6 != 2 {
		t.Fatalf("plages : %d IPv4, %d IPv6", v4, v6)
	}
	for ip, want := range map[string]uint32{
		"198.51.100.0": 64500, "198.51.100.255": 64500, "198.51.101.0": 0, "198.51.99.255": 0,
		"1.0.0.7": 13335, "203.0.113.200": 64501, "10.0.0.1": 0, "8.8.8.8": 0,
		"::ffff:198.51.100.9": 64500, // IPv4 mappée en IPv6
		"2001:db8::1":         64502, "2001:db9::1": 0, "2606:4700::6810:85e5": 13335,
	} {
		if got := db.Lookup(netip.MustParseAddr(ip)); got != want {
			t.Errorf("%s → AS%d, attendu AS%d", ip, got, want)
		}
	}
	var none *DB
	if none.Lookup(netip.MustParseAddr("1.0.0.1")) != 0 {
		t.Error("une base absente ne connaît personne")
	}
}

func TestSameContentSameVersion(t *testing.T) {
	a, va, _ := Encode([]Range{ra("1.0.0.0", "1.0.0.255", 1), ra("2.0.0.0", "2.0.0.255", 2)})
	b, vb, _ := Encode([]Range{ra("2.0.0.0", "2.0.0.255", 2), ra("1.0.0.0", "1.0.0.255", 1)})
	if va != vb || !bytes.Equal(a, b) {
		t.Fatalf("l'ordre d'entrée ne doit pas changer la version : %s / %s", va, vb)
	}
	_, vc, _ := Encode([]Range{ra("1.0.0.0", "1.0.0.255", 1)})
	if vc == va {
		t.Fatal("un contenu différent a une version différente")
	}
}

func TestDecodeRejectsGarbage(t *testing.T) {
	if _, err := Decode([]byte("pas du gzip")); err == nil {
		t.Error("gzip invalide")
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zw.Write([]byte("PAS-LE-BON-FORMAT")) //nolint:errcheck
	zw.Close()
	if _, err := Decode(buf.Bytes()); err == nil {
		t.Error("magic invalide")
	}
	buf.Reset()
	zw = gzip.NewWriter(&buf)
	zw.Write([]byte(magic + "\xff\xff\xff\xff\xff\xff\xff\xff\xff\x01")) //nolint:errcheck
	zw.Close()
	if _, err := Decode(buf.Bytes()); err == nil {
		t.Error("nombre de plages démesuré")
	}
	buf.Reset()
	zw = gzip.NewWriter(&buf)
	zw.Write([]byte(magic + "\x02\x01\x01\x01")) //nolint:errcheck // annonce 2 plages IPv4, n'en contient qu'une
	zw.Close()
	if _, err := Decode(buf.Bytes()); err == nil {
		t.Error("base tronquée")
	}
}
