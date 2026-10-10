// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/netip"
	"reflect"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/asn"
)

// Tout un ASN se lit par ses plages (index ip, ts) et non par toute la période de logs (502 après 30 s).
func TestASNLogBounds(t *testing.T) {
	rg := func(a, b string) asn.Range { return asn.Range{Start: netip.MustParseAddr(a), End: netip.MustParseAddr(b)} }
	got, ok := asnLogBounds([]asn.Range{
		rg("14.102.84.0", "14.102.87.255"), // /22 : bornée à « 14.102. »
		rg("14.102.90.0", "14.102.90.255"), // englobée par la précédente
		rg("5.0.0.9", "5.0.0.9"),
		rg("2001:db8::", "2001:db8::ffff"),
	})
	want := [][2]string{{"14.102.", "14.102.\x7f"}, {"2001:db8:", "2001:db8:\x7f"}, {"5.0.0.9", "5.0.0.9\x00"}}
	if !ok || !reflect.DeepEqual(got, want) {
		t.Fatalf("bornes = %q (%v), attendu %q", got, ok, want)
	}

	var many []asn.Range
	for i := 0; i < 2*traceMaxBounds; i++ {
		a := netip.AddrFrom4([4]byte{byte(20 + i/256), byte(i % 256), 0, 0})
		many = append(many, rg(a.String(), netip.AddrFrom4([4]byte{byte(20 + i/256), byte(i % 256), 0, 255}).String()))
	}
	if got, ok := asnLogBounds(many); !ok || len(got) != 8 || got[0][0] != "20." {
		t.Fatalf("ASN étendu : %d bornes (%v), attendu 8 regroupées par premier octet", len(got), ok)
	}

	if _, ok := asnLogBounds([]asn.Range{rg("0.0.0.0", "1.255.255.255")}); ok {
		t.Error("une plage plus large qu'un octet ne se borne pas : lecture complète attendue")
	}
}
