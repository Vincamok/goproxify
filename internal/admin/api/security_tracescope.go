// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"fmt"
	"net/netip"
	"sort"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/asn"
	"github.com/vincamok/goproxify/internal/admin/security"
)

// Étendue d'un traçage : l'adresse seule (ip, défaut), la plage que son opérateur annonce (range) ou tout
// l'ASN (asn). Les deux dernières s'appuient sur la base ASN : l'utilisateur n'a plus à connaître le CIDR.
const (
	TraceScopeIP    = "ip"
	TraceScopeRange = "range"
	TraceScopeASN   = "asn"
)

// traceMatcher décide quelles adresses et quels bans appartiennent au parcours. Le préfixe de la cible en
// est le cas par défaut.
type traceMatcher struct {
	contains func(netip.Addr) bool
	overlaps func(netip.Prefix) bool
	// sqlPrefix borne la lecture des logs ; sqlBounds (tout un ASN) la borne par plusieurs plages de la
	// colonne ip ; sans l'un ni l'autre, scanAll lit toute la période et le tri se fait en mémoire.
	sqlPrefix *netip.Prefix
	sqlBounds [][2]string
	scanAll   bool
}

// traceMaxBounds plafonne le nombre de plages d'une requête : au-delà, les plages sont regroupées par
// premier octet (IPv4) ou premier groupe (IPv6), plus larges mais en nombre borné.
const traceMaxBounds = 1000

// asnLogBounds traduit les plages d'un ASN en bornes de la colonne ip (texte), en les élargissant au
// préfixe qui les couvre : le surplus est écarté en mémoire par matchIP. ok vaut false si une plage ne
// se borne pas (préfixe plus large qu'un octet).
func asnLogBounds(ranges []asn.Range) ([][2]string, bool) {
	bounds, ok := asnLogBoundsAt(ranges, false)
	if ok && len(bounds) > traceMaxBounds {
		bounds, ok = asnLogBoundsAt(ranges, true)
	}
	return bounds, ok && len(bounds) > 0
}

func asnLogBoundsAt(ranges []asn.Range, coarse bool) ([][2]string, bool) {
	var bounds [][2]string
	for _, r := range ranges {
		p := coveringPrefix(r)
		maxBits := 8
		if p.Addr().Is6() {
			maxBits = 16
		}
		if coarse && p.Bits() > maxBits {
			p = netip.PrefixFrom(p.Addr(), maxBits).Masked()
		}
		lo, hi, ok := security.TraceIPRange(p)
		if !ok {
			return nil, false
		}
		bounds = append(bounds, [2]string{lo, hi})
	}
	sort.Slice(bounds, func(i, j int) bool { return bounds[i][0] < bounds[j][0] })
	// Une borne de préfixe (« 14.102. ») englobe celles qui commencent par elle.
	out := bounds[:0]
	for _, b := range bounds {
		if n := len(out); n > 0 {
			last := out[n-1][0]
			if b[0] == last || (strings.HasSuffix(last, ".") || strings.HasSuffix(last, ":")) && strings.HasPrefix(b[0], last) {
				continue
			}
		}
		out = append(out, b)
	}
	return out, true
}

func (m *traceMatcher) matchIP(target netip.Prefix, ip string) bool {
	if m.contains == nil {
		return security.TraceMatch(target, ip)
	}
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	return err == nil && m.contains(a.Unmap())
}

func (m *traceMatcher) overlap(target netip.Prefix, v string) bool {
	if m.overlaps == nil {
		return security.TraceOverlap(target, v)
	}
	p, err := security.ParseTraceTarget(v)
	return err == nil && m.overlaps(p)
}

// coveringPrefix retourne le plus petit préfixe qui contient les deux bornes d'une plage.
func coveringPrefix(r asn.Range) netip.Prefix {
	for bits := r.Start.BitLen(); bits >= 0; bits-- {
		p := netip.PrefixFrom(r.Start, bits).Masked()
		if p.Contains(r.End) {
			return p
		}
	}
	return netip.PrefixFrom(r.Start, 0).Masked()
}

func rangeOverlaps(r asn.Range, p netip.Prefix) bool {
	first, last := p.Masked().Addr().Unmap(), lastOfPrefix(p)
	return first.Is4() == r.Start.Is4() && !last.Less(r.Start) && !r.End.Less(first)
}

func lastOfPrefix(p netip.Prefix) netip.Addr {
	b := p.Masked().Addr().Unmap().AsSlice()
	bits := p.Bits()
	if p.Addr().Is4In6() {
		bits -= 96
	}
	for i := bits; i < len(b)*8; i++ {
		b[i/8] |= 1 << (7 - i%8)
	}
	a, _ := netip.AddrFromSlice(b)
	return a
}

// ResolveTraceScope applique l'étendue demandée à la requête et renseigne qy.Context, le contexte ASN de la
// cible (absent si la base ASN n'est pas installée ou ne connaît pas l'adresse).
//
// Avec l'étendue ip, la base n'est consultée que si elle est déjà installée : un simple traçage ne
// déclenche jamais un téléchargement. Les étendues range et asn la chargent (et la téléchargent au
// besoin), et échouent si elle est indisponible.
func ResolveTraceScope(ctx context.Context, db *sql.DB, store *asn.Store, qy *TraceQuery) error {
	scope := qy.Scope
	if scope == "" {
		scope = TraceScopeIP
	}
	switch scope {
	case TraceScopeIP, TraceScopeRange, TraceScopeASN:
	default:
		return fmt.Errorf("scope inconnu %q (ip, range ou asn)", scope)
	}
	qy.Scope = scope
	qy.matcher = traceMatcher{}

	var idx *asn.Index
	if scope == TraceScopeIP {
		if store != nil {
			idx, _ = store.Installed(ctx)
		}
	} else {
		if store == nil {
			return ErrASNUnavailable
		}
		var err error
		if idx, err = store.Index(ctx); err != nil {
			return fmt.Errorf("%w : %v", ErrASNUnavailable, err)
		}
	}

	// ASN demandé explicitement (sans IP) : il fixe l'étendue asn.
	var entry *asn.Entry
	var rng asn.Range
	found := false
	if qy.ASN != "" {
		if scope != TraceScopeASN {
			return fmt.Errorf("le paramètre asn s'utilise avec scope=asn")
		}
		e, err := resolveASN(ctx, store, qy.ASN)
		if err != nil {
			return err
		}
		entry, found = e, true
	} else if idx != nil {
		if e, r, ok := idx.Find(qy.Target.Addr()); ok {
			entry, rng, found = e, r, true
		}
	}

	switch scope {
	case TraceScopeRange:
		if !found {
			return fmt.Errorf("%w : aucune plage annoncée ne contient %s (adresse privée, réservée ou absente du jeu de données)", ErrASNUnknown, qy.Target.Addr())
		}
		cover := coveringPrefix(rng)
		qy.matcher = traceMatcher{
			contains:  func(a netip.Addr) bool { return !a.Less(rng.Start) && !rng.End.Less(a) && a.Is4() == rng.Start.Is4() },
			overlaps:  func(p netip.Prefix) bool { return rangeOverlaps(rng, p) },
			sqlPrefix: &cover,
		}
		qy.ScopeLabel = fmt.Sprintf("%s – %s (AS%d %s)", rng.Start, rng.End, entry.ASN, entry.Name)
	case TraceScopeASN:
		if !found {
			return fmt.Errorf("%w : aucun ASN ne contient %s (adresse privée, réservée ou absente du jeu de données)", ErrASNUnknown, qy.Target.Addr())
		}
		bounds, ok := asnLogBounds(entry.Ranges)
		qy.matcher = traceMatcher{contains: entry.Contains, overlaps: entry.Overlaps, sqlBounds: bounds, scanAll: !ok}
		qy.ScopeLabel = fmt.Sprintf("AS%d %s", entry.ASN, entry.Name)
	}

	if !found {
		return nil
	}
	info := asnInfo(db, entry)
	ctxInfo := map[string]any{"asn": info}
	if rng.Start.IsValid() {
		cidrs := []string{}
		for _, p := range asn.RangeToPrefixes(rng) {
			cidrs = append(cidrs, p.String())
		}
		ctxInfo["range"] = map[string]any{"start": rng.Start.String(), "end": rng.End.String(), "cidrs": cidrs}
	}
	qy.Context = ctxInfo
	return nil
}
