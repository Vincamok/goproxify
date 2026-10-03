// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"fmt"
	"net/netip"
	"sort"
	"strings"
	"time"
)

// ParseTraceTarget lit une IP ou un CIDR ; une IP seule devient son préfixe /32 (/128).
func ParseTraceTarget(s string) (netip.Prefix, error) {
	s = strings.TrimSpace(s)
	p, err := netip.ParsePrefix(s)
	if err != nil {
		a, aerr := netip.ParseAddr(s)
		if aerr != nil {
			return netip.Prefix{}, fmt.Errorf("IP ou CIDR invalide : %q", s)
		}
		p = netip.PrefixFrom(a, a.BitLen())
	}
	if p.Addr().Is4In6() && p.Bits() >= 96 {
		p = netip.PrefixFrom(p.Addr().Unmap(), p.Bits()-96)
	}
	return p.Masked(), nil
}

// TraceIPRange donne l'intervalle [lo, hi) de la colonne texte ip qui contient toute adresse du
// préfixe (ok=false : aucune restriction possible). C'est un sur-ensemble aligné sur les octets
// (IPv4) ou les groupes avant le premier groupe nul (IPv6, dont la forme canonique compresse les
// zéros) : le filtre exact reste à faire avec TraceMatch. Un intervalle, pas un LIKE, pour
// utiliser l'index idx_logs_ip_ts.
func TraceIPRange(p netip.Prefix) (lo, hi string, ok bool) {
	a := p.Addr()
	if a.Is4() {
		n := p.Bits() / 8
		if n == 0 {
			return "", "", false
		}
		if n >= 4 {
			return a.String(), a.String() + "\x00", true
		}
		b := a.As4()
		parts := make([]string, n)
		for i := range parts {
			parts[i] = fmt.Sprint(b[i])
		}
		lo = strings.Join(parts, ".") + "."
		return lo, lo + "\x7f", true
	}
	b := a.As16()
	var sb strings.Builder
	for i := 0; i < p.Bits()/16 && i < 8; i++ {
		h := uint16(b[2*i])<<8 | uint16(b[2*i+1])
		if h == 0 {
			break
		}
		fmt.Fprintf(&sb, "%x:", h)
	}
	if sb.Len() == 0 {
		return "", "", false
	}
	lo = sb.String()
	return lo, lo + "\x7f", true
}

// TraceMatch indique si l'IP texte appartient à la cible.
func TraceMatch(target netip.Prefix, ip string) bool {
	a, err := netip.ParseAddr(strings.TrimSpace(ip))
	if err != nil {
		return false
	}
	return target.Contains(a.Unmap())
}

// TraceOverlap indique si la valeur d'un ban (IP ou CIDR) recoupe la cible : un ban sur un /24
// concerne une IP qu'il contient, et inversement.
func TraceOverlap(target netip.Prefix, v string) bool {
	p, err := ParseTraceTarget(v)
	return err == nil && target.Overlaps(p)
}

// TraceGap sépare deux épisodes d'activité d'une même cible.
const TraceGap = 10 * time.Minute

// TraceRequest est une requête d'accès observée sur la cible.
type TraceRequest struct {
	Ts           time.Time
	IP           string
	Domain       string
	Method       string
	Path         string
	Status       int
	Node         string
	WAFMatches   []string
	ThreatSignal string
}

// TraceBurst regroupe les requêtes consécutives de la cible (écart < TraceGap) : un an de trafic
// d'un scanner se lit en quelques centaines d'étapes plutôt qu'en millions de lignes.
type TraceBurst struct {
	Start        time.Time      `json:"start"`
	End          time.Time      `json:"end"`
	Requests     int            `json:"requests"`
	Blocked      int            `json:"blocked"`
	IPs          []string       `json:"ips"`
	IPCount      int            `json:"ip_count"`
	Domains      []string       `json:"domains"`
	Nodes        []string       `json:"nodes,omitempty"`
	Statuses     map[string]int `json:"statuses"`
	TopPaths     []TraceCount   `json:"top_paths"`
	WAFMatches   []TraceCount   `json:"waf_matches,omitempty"`
	ThreatSignal []TraceCount   `json:"threat_signals,omitempty"`

	ips, domains, nodes  map[string]int
	paths, waf, threatSg map[string]int
}

// TraceCount est une valeur et son nombre d'occurrences.
type TraceCount struct {
	Value string `json:"value"`
	Count int    `json:"count"`
}

// traceBlocked : refus explicite de la passerelle (403, 429) ou protection déclenchée.
func traceBlocked(r TraceRequest) bool {
	return r.Status == 403 || r.Status == 429 || len(r.WAFMatches) > 0 || r.ThreatSignal != ""
}

func newBurst(r TraceRequest) *TraceBurst {
	return &TraceBurst{
		Start: r.Ts, End: r.Ts, Statuses: map[string]int{},
		ips: map[string]int{}, domains: map[string]int{}, nodes: map[string]int{},
		paths: map[string]int{}, waf: map[string]int{}, threatSg: map[string]int{},
	}
}

func (b *TraceBurst) add(r TraceRequest) {
	b.End = r.Ts
	b.Requests++
	if traceBlocked(r) {
		b.Blocked++
	}
	b.Statuses[fmt.Sprintf("%dxx", r.Status/100)]++
	b.ips[r.IP]++
	if r.Domain != "" {
		b.domains[r.Domain]++
	}
	if r.Node != "" {
		b.nodes[r.Node]++
	}
	if r.Path != "" {
		b.paths[r.Method+" "+r.Path]++
	}
	for _, m := range r.WAFMatches {
		b.waf[m]++
	}
	if r.ThreatSignal != "" {
		b.threatSg[r.ThreatSignal]++
	}
}

// TopCounts trie par fréquence décroissante puis alphabétique, et garde n valeurs.
func TopCounts(m map[string]int, n int) []TraceCount {
	out := make([]TraceCount, 0, len(m))
	for v, c := range m {
		out = append(out, TraceCount{v, c})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Count != out[j].Count {
			return out[i].Count > out[j].Count
		}
		return out[i].Value < out[j].Value
	})
	if len(out) > n {
		out = out[:n]
	}
	return out
}

func (b *TraceBurst) finish() {
	b.IPCount = len(b.ips)
	b.IPs = keys(TopCounts(b.ips, 5))
	b.Domains = keys(TopCounts(b.domains, 5))
	b.Nodes = keys(TopCounts(b.nodes, 5))
	b.TopPaths = TopCounts(b.paths, 5)
	b.WAFMatches = TopCounts(b.waf, 5)
	b.ThreatSignal = TopCounts(b.threatSg, 5)
	b.ips, b.domains, b.nodes, b.paths, b.waf, b.threatSg = nil, nil, nil, nil, nil, nil
}

func keys(c []TraceCount) []string {
	out := make([]string, len(c))
	for i, v := range c {
		out[i] = v.Value
	}
	return out
}

// BurstBuilder construit les épisodes au fil d'un parcours trié, sans garder les requêtes.
type BurstBuilder struct {
	Bursts []*TraceBurst
	cur    *TraceBurst
}

// Add ajoute une requête (ordre chronologique).
func (bb *BurstBuilder) Add(r TraceRequest) {
	if bb.cur == nil || r.Ts.Sub(bb.cur.End) >= TraceGap {
		if bb.cur != nil {
			bb.cur.finish()
		}
		bb.cur = newBurst(r)
		bb.Bursts = append(bb.Bursts, bb.cur)
	}
	bb.cur.add(r)
}

// Done clôt le dernier épisode.
func (bb *BurstBuilder) Done() {
	if bb.cur != nil {
		bb.cur.finish()
		bb.cur = nil
	}
}
