// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package asn relie les adresses IP aux systèmes autonomes (ASN) à partir du jeu de données public
// ip2asn de iptoasn.com (domaine public) : quel ASN annonce une adresse, et quelles plages annonce un ASN.
// Il sert à bannir un ASN en bloquant l'ensemble de ses plages ; les passerelles n'en ont pas besoin.
package asn

import (
	"bufio"
	"compress/gzip"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
)

// Range est une plage d'adresses contiguë, bornes incluses.
type Range struct{ Start, End netip.Addr }

// Entry regroupe ce que l'on sait d'un ASN.
type Entry struct {
	ASN     uint32
	Name    string
	Country string
	Ranges  []Range // triées, sans chevauchement
}

// Addresses est le nombre d'adresses annoncées (approximatif pour IPv6, au-delà de 2^53).
func (e *Entry) Addresses() float64 {
	var n float64
	for _, r := range e.Ranges {
		n += addrFloat(r.End) - addrFloat(r.Start) + 1
	}
	return n
}

type lookupRange struct {
	start, end netip.Addr
	asn        uint32
}

// Index est le jeu de données chargé en mémoire.
type Index struct {
	byASN  map[uint32]*Entry
	sorted []lookupRange
}

// Parse lit le format ip2asn : une plage par ligne, séparée par des tabulations
// (début, fin, ASN, pays, nom). Les plages non annoncées (ASN 0) sont ignorées.
func Parse(r io.Reader) (*Index, error) {
	idx := &Index{byASN: map[uint32]*Entry{}}
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1<<20), 1<<20)
	for line := 1; sc.Scan(); line++ {
		text := strings.TrimSpace(sc.Text())
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		f := strings.Split(text, "\t")
		if len(f) < 3 {
			return nil, fmt.Errorf("ligne %d : au moins 3 colonnes séparées par des tabulations attendues", line)
		}
		n, err := strconv.ParseUint(f[2], 10, 32)
		if err != nil {
			return nil, fmt.Errorf("ligne %d : ASN %q illisible", line, f[2])
		}
		if n == 0 {
			continue
		}
		start, e1 := netip.ParseAddr(f[0])
		end, e2 := netip.ParseAddr(f[1])
		if e1 != nil || e2 != nil || start.Is4() != end.Is4() || end.Less(start) {
			return nil, fmt.Errorf("ligne %d : plage %s – %s invalide", line, f[0], f[1])
		}
		e := idx.byASN[uint32(n)]
		if e == nil {
			e = &Entry{ASN: uint32(n)}
			if len(f) > 3 && f[3] != "None" {
				e.Country = f[3]
			}
			if len(f) > 4 {
				e.Name = f[4]
			}
			idx.byASN[uint32(n)] = e
		}
		e.Ranges = append(e.Ranges, Range{start, end})
		idx.sorted = append(idx.sorted, lookupRange{start, end, uint32(n)})
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	for _, e := range idx.byASN {
		e.Ranges = mergeRanges(e.Ranges)
	}
	sort.Slice(idx.sorted, func(i, j int) bool { return idx.sorted[i].start.Less(idx.sorted[j].start) })
	return idx, nil
}

// ParseGzip lit le même format compressé.
func ParseGzip(r io.Reader) (*Index, error) {
	zr, err := gzip.NewReader(r)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	return Parse(zr)
}

// Len retourne le nombre d'ASN et de plages.
func (x *Index) Len() (asns, ranges int) { return len(x.byASN), len(x.sorted) }

// Get retourne un ASN connu.
func (x *Index) Get(asn uint32) (*Entry, bool) {
	e, ok := x.byASN[asn]
	return e, ok
}

// ByIP retourne l'ASN qui annonce l'adresse.
func (x *Index) ByIP(a netip.Addr) (*Entry, bool) {
	a = a.Unmap()
	i := sort.Search(len(x.sorted), func(i int) bool { return a.Less(x.sorted[i].start) })
	// Les plages de ip2asn ne se chevauchent pas : la candidate est la dernière qui commence avant a.
	for j := i - 1; j >= 0 && j >= i-1; j-- {
		r := x.sorted[j]
		if r.start.Is4() == a.Is4() && !a.Less(r.start) && !r.end.Less(a) {
			return x.byASN[r.asn], true
		}
	}
	return nil, false
}

// Contains dit si l'adresse appartient à l'une des plages de l'ASN.
func (e *Entry) Contains(a netip.Addr) bool {
	a = a.Unmap()
	i := sort.Search(len(e.Ranges), func(i int) bool { return a.Less(e.Ranges[i].Start) })
	if i == 0 {
		return false
	}
	r := e.Ranges[i-1]
	return r.Start.Is4() == a.Is4() && !r.End.Less(a)
}

// Search retourne jusqu'à limit ASN dont le nom contient q (sans tenir compte de la casse), les plus
// grands d'abord.
func (x *Index) Search(q string, limit int) []*Entry {
	q = strings.ToLower(strings.TrimSpace(q))
	if q == "" {
		return nil
	}
	var out []*Entry
	for _, e := range x.byASN {
		if strings.Contains(strings.ToLower(e.Name), q) {
			out = append(out, e)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if a, b := out[i].Addresses(), out[j].Addresses(); a != b {
			return a > b
		}
		return out[i].ASN < out[j].ASN
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out
}

// ParseASN accepte « AS16276 », « as16276 » ou « 16276 ».
func ParseASN(s string) (uint32, bool) {
	s = strings.TrimSpace(s)
	if len(s) > 2 && strings.EqualFold(s[:2], "as") {
		s = s[2:]
	}
	n, err := strconv.ParseUint(s, 10, 32)
	return uint32(n), err == nil && n > 0
}

// mergeRanges trie les plages et fusionne celles qui se chevauchent ou se touchent.
func mergeRanges(in []Range) []Range {
	sort.Slice(in, func(i, j int) bool { return in[i].Start.Less(in[j].Start) })
	var out []Range
	for _, r := range in {
		if n := len(out); n > 0 && out[n-1].Start.Is4() == r.Start.Is4() {
			last := &out[n-1]
			if next := last.End.Next(); next.IsValid() && !next.Less(r.Start) || !last.End.Less(r.Start) {
				if last.End.Less(r.End) {
					last.End = r.End
				}
				continue
			}
		}
		out = append(out, r)
	}
	return out
}
