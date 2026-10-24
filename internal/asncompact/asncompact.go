// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package asncompact est la forme compacte de la base IP → ASN que l'Admin pousse aux passerelles (ADR 0011) : trois entiers par
// plage IPv4, une plage IPv6 en deux adresses et un entier, le tout compressé. Une passerelle y cherche l'ASN d'une adresse sans
// rien savoir des noms ni des pays ; elle en garde une copie chiffrée et n'a plus besoin de l'Admin pour s'en servir.
package asncompact

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"
)

const (
	magic = "GPXASN1"

	maxRanges       = 4_000_000 // garde-fou à la lecture
	maxDecompressed = 128 << 20 // idem : une base de plusieurs millions de plages tient dans 30 Mo
	versionLen      = 12
)

// Range est une plage d'adresses contiguë, bornes incluses, annoncée par un ASN.
type Range struct {
	Start, End netip.Addr
	ASN        uint32
}

// Encode sérialise et compresse les plages. Retourne aussi la version du contenu (empreinte), qui permet à une passerelle de
// savoir si elle a déjà cette base.
func Encode(ranges []Range) (data []byte, version string, err error) {
	var v4, v6 []Range
	for _, r := range ranges {
		s, e := r.Start.Unmap(), r.End.Unmap()
		if !s.IsValid() || !e.IsValid() || s.Is4() != e.Is4() || e.Less(s) || r.ASN == 0 {
			continue
		}
		r.Start, r.End = s, e
		if s.Is4() {
			v4 = append(v4, r)
		} else {
			v6 = append(v6, r)
		}
	}
	sortRanges(v4)
	sortRanges(v6)

	var raw bytes.Buffer
	raw.WriteString(magic)
	var tmp [binary.MaxVarintLen64]byte
	put := func(v uint64) { raw.Write(tmp[:binary.PutUvarint(tmp[:], v)]) }

	put(uint64(len(v4)))
	var prev uint32
	for _, r := range v4 {
		s, e := addr4(r.Start), addr4(r.End)
		put(uint64(s - prev))
		put(uint64(e - s))
		put(uint64(r.ASN))
		prev = s
	}
	put(uint64(len(v6)))
	for _, r := range v6 {
		s, e := r.Start.As16(), r.End.As16()
		raw.Write(s[:])
		raw.Write(e[:])
		put(uint64(r.ASN))
	}

	sum := sha256.Sum256(raw.Bytes())
	version = hex.EncodeToString(sum[:])[:versionLen]

	var out bytes.Buffer
	zw, err := gzip.NewWriterLevel(&out, gzip.BestCompression)
	if err != nil {
		return nil, "", err
	}
	if _, err := zw.Write(raw.Bytes()); err != nil {
		return nil, "", err
	}
	if err := zw.Close(); err != nil {
		return nil, "", err
	}
	return out.Bytes(), version, nil
}

func sortRanges(r []Range) {
	sort.SliceStable(r, func(i, j int) bool { return r[i].Start.Less(r[j].Start) })
}

func addr4(a netip.Addr) uint32 {
	b := a.As4()
	return binary.BigEndian.Uint32(b[:])
}

// DB est la base chargée en mémoire : recherche binaire, sans allocation.
type DB struct {
	v4s, v4e, v4a []uint32
	v6s, v6e      [][16]byte
	v6a           []uint32
	version       string
}

// Decode relit une base produite par Encode.
func Decode(data []byte) (*DB, error) {
	zr, err := gzip.NewReader(bytes.NewReader(data))
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	raw, err := io.ReadAll(io.LimitReader(zr, maxDecompressed+1))
	if err != nil {
		return nil, err
	}
	if len(raw) > maxDecompressed {
		return nil, errors.New("asncompact : base trop grande")
	}
	if len(raw) < len(magic) || string(raw[:len(magic)]) != magic {
		return nil, errors.New("asncompact : format inconnu")
	}
	sum := sha256.Sum256(raw)
	d := &DB{version: hex.EncodeToString(sum[:])[:versionLen]}
	r := bytes.NewReader(raw[len(magic):])
	get := func() (uint64, error) { return binary.ReadUvarint(r) }

	n4, err := get()
	if err != nil || n4 > maxRanges {
		return nil, fmt.Errorf("asncompact : nombre de plages IPv4 invalide")
	}
	d.v4s, d.v4e, d.v4a = make([]uint32, 0, n4), make([]uint32, 0, n4), make([]uint32, 0, n4)
	var prev uint32
	for i := uint64(0); i < n4; i++ {
		delta, e1 := get()
		length, e2 := get()
		asn, e3 := get()
		if e1 != nil || e2 != nil || e3 != nil || delta > 1<<32 || length > 1<<32 || asn == 0 || asn > 1<<32-1 {
			return nil, errors.New("asncompact : plage IPv4 illisible")
		}
		start := prev + uint32(delta)
		if uint64(start)+length > 1<<32-1 {
			return nil, errors.New("asncompact : plage IPv4 hors limites")
		}
		d.v4s = append(d.v4s, start)
		d.v4e = append(d.v4e, start+uint32(length))
		d.v4a = append(d.v4a, uint32(asn))
		prev = start
	}
	n6, err := get()
	if err != nil || n6 > maxRanges {
		return nil, errors.New("asncompact : nombre de plages IPv6 invalide")
	}
	for i := uint64(0); i < n6; i++ {
		var s, e [16]byte
		if _, err := io.ReadFull(r, s[:]); err != nil {
			return nil, errors.New("asncompact : plage IPv6 illisible")
		}
		if _, err := io.ReadFull(r, e[:]); err != nil {
			return nil, errors.New("asncompact : plage IPv6 illisible")
		}
		asn, err := get()
		if err != nil || asn == 0 || asn > 1<<32-1 {
			return nil, errors.New("asncompact : plage IPv6 illisible")
		}
		d.v6s, d.v6e, d.v6a = append(d.v6s, s), append(d.v6e, e), append(d.v6a, uint32(asn))
	}
	return d, nil
}

// Version retourne l'empreinte du contenu.
func (d *DB) Version() string { return d.version }

// Len retourne le nombre de plages IPv4 et IPv6.
func (d *DB) Len() (v4, v6 int) { return len(d.v4s), len(d.v6s) }

// Lookup retourne l'ASN qui annonce l'adresse, 0 si elle n'est annoncée par personne.
func (d *DB) Lookup(a netip.Addr) uint32 {
	if d == nil {
		return 0
	}
	a = a.Unmap()
	if a.Is4() {
		v := addr4(a)
		i := sort.Search(len(d.v4s), func(i int) bool { return d.v4s[i] > v })
		if i > 0 && v <= d.v4e[i-1] {
			return d.v4a[i-1]
		}
		return 0
	}
	if !a.IsValid() {
		return 0
	}
	b := a.As16()
	i := sort.Search(len(d.v6s), func(i int) bool { return bytes.Compare(d.v6s[i][:], b[:]) > 0 })
	if i > 0 && bytes.Compare(b[:], d.v6e[i-1][:]) <= 0 {
		return d.v6a[i-1]
	}
	return 0
}
