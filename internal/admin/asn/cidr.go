// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package asn

import "net/netip"

// Plus large plage bannissable : /16 en IPv4, /32 en IPv6 (mêmes bornes qu'un ban manuel). Une plage
// annoncée plus large est découpée en plages de cette taille.
const (
	banMinBitsV4 = 16
	banMinBitsV6 = 32
	// maxSplit borne le découpage d'une plage trop large : un /19 IPv6 donnerait 8 192 plages /32.
	maxSplit = 1024
)

// RangeToPrefixes découpe une plage contiguë en la plus courte liste de CIDR qui la couvre exactement.
func RangeToPrefixes(r Range) []netip.Prefix {
	var out []netip.Prefix
	start := r.Start
	for start.IsValid() && !r.End.Less(start) {
		var taken netip.Prefix
		for bits := 0; bits <= start.BitLen(); bits++ {
			p := netip.PrefixFrom(start, bits)
			if p.Masked().Addr() != start {
				continue
			}
			if last := lastAddr(p); !r.End.Less(last) {
				taken = p
				break
			}
		}
		out = append(out, taken)
		start = lastAddr(taken).Next()
	}
	return out
}

func lastAddr(p netip.Prefix) netip.Addr {
	b := p.Addr().AsSlice()
	for i := p.Bits(); i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// BanPrefixes retourne les plages à bannir pour bloquer l'ASN. Les plages plus larges que ce qu'un ban
// accepte sont découpées ; skipped compte celles dont le découpage dépasserait maxSplit.
func (e *Entry) BanPrefixes() (prefixes []netip.Prefix, skipped int) {
	for _, r := range e.Ranges {
		for _, p := range RangeToPrefixes(r) {
			min := banMinBitsV6
			if p.Addr().Is4() {
				min = banMinBitsV4
			}
			if p.Bits() >= min {
				prefixes = append(prefixes, p)
				continue
			}
			if p.Bits() < min-10 {
				skipped++
				continue
			}
			base := p.Addr()
			for i := 0; i < 1<<(min-p.Bits()); i++ {
				prefixes = append(prefixes, netip.PrefixFrom(base, min))
				next := lastAddr(netip.PrefixFrom(base, min)).Next()
				if !next.IsValid() {
					break
				}
				base = next
			}
		}
	}
	return prefixes, skipped
}

// addrFloat convertit une adresse en nombre (perte de précision au-delà de 2^53, sans conséquence pour
// un décompte d'adresses).
func addrFloat(a netip.Addr) float64 {
	var f float64
	for _, b := range a.AsSlice() {
		f = f*256 + float64(b)
	}
	return f
}
