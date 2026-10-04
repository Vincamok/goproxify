// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package asn

import (
	"bytes"
	"compress/gzip"
	"context"
	"net/http"
	"net/http/httptest"
	"net/netip"
	"path/filepath"
	"strings"
	"testing"
)

const sample = "1.0.0.0\t1.0.0.255\t13335\tUS\tCLOUDFLARENET\n" +
	"1.0.1.0\t1.0.3.255\t0\tNone\tNot routed\n" +
	"5.0.0.0\t5.0.0.255\t64500\tFR\tEXEMPLE-HEBERGEUR\n" +
	"5.0.1.0\t5.0.1.255\t64500\tFR\tEXEMPLE-HEBERGEUR\n" +
	"5.0.8.0\t5.0.8.127\t64500\tFR\tEXEMPLE-HEBERGEUR\n" +
	"9.0.0.0\t9.7.255.255\t64501\tFR\tGRAND-OPERATEUR\n" +
	"2001:db8::\t2001:db8:ffff:ffff:ffff:ffff:ffff:ffff\t64500\tFR\tEXEMPLE-HEBERGEUR\n"

func mustIndex(t *testing.T) *Index {
	t.Helper()
	idx, err := Parse(strings.NewReader(sample))
	if err != nil {
		t.Fatal(err)
	}
	return idx
}

func TestParseSkipsUnroutedAndMergesTouchingRanges(t *testing.T) {
	idx := mustIndex(t)
	asns, ranges := idx.Len()
	if asns != 3 || ranges != 6 {
		t.Fatalf("%d ASN, %d plages", asns, ranges)
	}
	e, ok := idx.Get(64500)
	if !ok || e.Name != "EXEMPLE-HEBERGEUR" || e.Country != "FR" {
		t.Fatalf("ASN 64500 : %+v", e)
	}
	// 5.0.0.0/24 et 5.0.1.0/24 se touchent : une plage. 5.0.8.0/25 est à part. Plus l'IPv6.
	if len(e.Ranges) != 3 || e.Ranges[0].End.String() != "5.0.1.255" {
		t.Fatalf("plages fusionnées : %+v", e.Ranges)
	}
	if got := e.V4Addresses(); got != 512+128 {
		t.Errorf("adresses : %v", got)
	}
}

func TestParseRejectsGarbage(t *testing.T) {
	for _, bad := range []string{"pas un tsv\n", "1.0.0.0\t1.0.0.255\tabc\tUS\tx\n", "1.0.0.255\t1.0.0.0\t1\tUS\tx\n", "1.0.0.0\t::1\t1\tUS\tx\n"} {
		if _, err := Parse(strings.NewReader(bad)); err == nil {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestByIPAndContains(t *testing.T) {
	idx := mustIndex(t)
	for ip, want := range map[string]uint32{"1.0.0.7": 13335, "5.0.1.200": 64500, "5.0.8.100": 64500, "9.3.4.5": 64501, "2001:db8::1": 64500} {
		e, ok := idx.ByIP(netip.MustParseAddr(ip))
		if !ok || e.ASN != want {
			t.Errorf("%s : %v %v (attendu %d)", ip, e, ok, want)
		}
	}
	for _, ip := range []string{"1.0.2.0", "5.0.8.128", "8.8.8.8", "0.0.0.1", "2001:db9::1"} {
		if e, ok := idx.ByIP(netip.MustParseAddr(ip)); ok {
			t.Errorf("%s ne devrait appartenir à aucun ASN (%d)", ip, e.ASN)
		}
	}
	e, _ := idx.Get(64500)
	if !e.Contains(netip.MustParseAddr("5.0.0.9")) || e.Contains(netip.MustParseAddr("5.0.2.0")) || !e.Contains(netip.MustParseAddr("::ffff:5.0.8.1")) {
		t.Error("Contains")
	}
}

func TestSearchAndParseASN(t *testing.T) {
	idx := mustIndex(t)
	got := idx.Search("exemple", 5)
	if len(got) != 1 || got[0].ASN != 64500 {
		t.Fatalf("recherche : %+v", got)
	}
	if got := idx.Search("e", 5); len(got) != 3 || got[0].ASN != 64501 {
		t.Errorf("tri par taille : %+v", got)
	}
	for in, want := range map[string]uint32{"AS64500": 64500, "as64500": 64500, " 64500 ": 64500} {
		if n, ok := ParseASN(in); !ok || n != want {
			t.Errorf("%q : %d %v", in, n, ok)
		}
	}
	for _, bad := range []string{"", "AS", "AS0", "0", "ASx", "1.2.3.4"} {
		if _, ok := ParseASN(bad); ok {
			t.Errorf("%q accepté", bad)
		}
	}
}

func TestRangeToPrefixes(t *testing.T) {
	var got []string
	for _, p := range RangeToPrefixes(Range{netip.MustParseAddr("1.0.1.0"), netip.MustParseAddr("1.0.3.255")}) {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "1.0.1.0/24 1.0.2.0/23" {
		t.Errorf("1.0.1.0–1.0.3.255 : %v", got)
	}
	got = nil
	for _, p := range RangeToPrefixes(Range{netip.MustParseAddr("10.0.0.3"), netip.MustParseAddr("10.0.0.10")}) {
		got = append(got, p.String())
	}
	if strings.Join(got, " ") != "10.0.0.3/32 10.0.0.4/30 10.0.0.8/31 10.0.0.10/32" {
		t.Errorf("plage non alignée : %v", got)
	}
	if p := RangeToPrefixes(Range{netip.MustParseAddr("0.0.0.0"), netip.MustParseAddr("255.255.255.255")}); len(p) != 1 || p[0].String() != "0.0.0.0/0" {
		t.Errorf("tout l'espace IPv4 : %v", p)
	}
}

func TestBanPrefixesSplitsWideRanges(t *testing.T) {
	idx := mustIndex(t)
	// 9.0.0.0–9.7.255.255 = 9.0.0.0/13 : huit /16.
	e, _ := idx.Get(64501)
	ps, skipped := e.BanPrefixes()
	if skipped != 0 || len(ps) != 8 || ps[0].String() != "9.0.0.0/16" || ps[7].String() != "9.7.0.0/16" {
		t.Fatalf("%v (ignorées : %d)", ps, skipped)
	}
	// L'IPv6 2001:db8::/32 est à la limite (/32) : gardée telle quelle.
	e, _ = idx.Get(64500)
	ps, _ = e.BanPrefixes()
	found := false
	for _, p := range ps {
		found = found || p.String() == "2001:db8::/32"
		if p.Addr().Is4() && p.Bits() < 16 || p.Addr().Is6() && p.Bits() < 32 {
			t.Errorf("plage trop large : %v", p)
		}
	}
	if !found {
		t.Errorf("2001:db8::/32 absent : %v", ps)
	}
	// Un /8 IPv4 (256 plages /16) reste découpable ; un /4 IPv6 (2^28 plages) est ignoré.
	wide := &Entry{Ranges: []Range{
		{netip.MustParseAddr("12.0.0.0"), netip.MustParseAddr("12.255.255.255")},
		{netip.MustParseAddr("2000::"), netip.MustParseAddr("2fff:ffff:ffff:ffff:ffff:ffff:ffff:ffff")},
	}}
	ps, skipped = wide.BanPrefixes()
	if len(ps) != 256 || skipped != 1 {
		t.Errorf("%d plages, %d ignorée(s)", len(ps), skipped)
	}
}

func gz(t *testing.T, s string) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	_, _ = zw.Write([]byte(s))
	_ = zw.Close()
	return buf.Bytes()
}

func TestStoreDownloadsOnceThenReloadsWhenFileChanges(t *testing.T) {
	hits := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		hits++
		_, _ = w.Write(gz(t, sample))
	}))
	defer srv.Close()
	path := filepath.Join(t.TempDir(), "asn", "ip2asn.tsv.gz")
	s := NewStore(path, srv.URL, nil)
	s.minRanges = 3

	if in := s.Info(); in.Installed {
		t.Fatal("rien d'installé au départ")
	}
	idx, err := s.Index(context.Background())
	if err != nil || hits != 1 {
		t.Fatalf("premier appel : %v, %d téléchargement(s)", err, hits)
	}
	if _, ok := idx.Get(13335); !ok {
		t.Error("ASN absent après téléchargement")
	}
	if _, err := s.Index(context.Background()); err != nil || hits != 1 {
		t.Errorf("second appel : %v, %d téléchargement(s) (aucun attendu)", err, hits)
	}
	in := s.Info()
	if !in.Installed || in.ASNs != 3 || in.Ranges != 6 {
		t.Errorf("info : %+v", in)
	}
	if err := s.Refresh(context.Background()); err != nil || hits != 2 {
		t.Errorf("rafraîchissement : %v, %d", err, hits)
	}
}

func TestStoreRefusesTruncatedOrBrokenDownloads(t *testing.T) {
	for name, handler := range map[string]http.HandlerFunc{
		"http 500":  func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) },
		"pas du gz": func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("<html>erreur</html>")) },
		"trop court": func(w http.ResponseWriter, r *http.Request) {
			_, _ = w.Write(gz(t, "1.0.0.0\t1.0.0.255\t13335\tUS\tX\n"))
		},
	} {
		srv := httptest.NewServer(handler)
		path := filepath.Join(t.TempDir(), "ip2asn.tsv.gz")
		s := NewStore(path, srv.URL, nil)
		if _, err := s.Index(context.Background()); err == nil {
			t.Errorf("%s : téléchargement accepté", name)
		}
		if in := s.Info(); in.Installed {
			t.Errorf("%s : un fichier invalide a été installé", name)
		}
		srv.Close()
	}
}

func TestFindAndOverlaps(t *testing.T) {
	idx := mustIndex(t)
	e, r, ok := idx.Find(netip.MustParseAddr("5.0.1.200"))
	if !ok || e.ASN != 64500 || r.Start.String() != "5.0.1.0" || r.End.String() != "5.0.1.255" {
		t.Fatalf("Find : %v %v %v", e, r, ok)
	}
	if _, _, ok := idx.Find(netip.MustParseAddr("8.8.8.8")); ok {
		t.Error("8.8.8.8 ne devrait pas être trouvée")
	}
	e, _ = idx.Get(64500)
	for p, want := range map[string]bool{
		"5.0.0.0/24": true, "5.0.1.0/24": true, "5.0.0.0/16": true, "5.0.8.64/26": true, "5.0.2.0/24": false,
		"5.0.8.128/25": false, "4.0.0.0/8": false, "2001:db8:1::/48": true, "2a00::/32": false,
	} {
		if got := e.Overlaps(netip.MustParsePrefix(p)); got != want {
			t.Errorf("Overlaps(%s) = %v, attendu %v", p, got, want)
		}
	}
}
