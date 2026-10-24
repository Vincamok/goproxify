// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package ipsketch compte des IP distinctes à travers plusieurs sources sans rien stocker de plus (ADR 0012). Chaque
// passerelle résume l'ensemble qu'elle voit ; l'Admin fait l'union des résumés. Tant que l'ensemble tient dans
// ExactLimit adresses il est transmis tel quel (le compte est exact) ; au-delà il devient un sketch HyperLogLog
// d'environ 0,8 % d'erreur, dont l'union reste sans double compte.
package ipsketch

import (
	"encoding/base64"
	"errors"
	"hash/fnv"
	"math"
	"math/bits"
)

const (
	// ExactLimit : au-delà, le résumé passe en estimation.
	ExactLimit = 2000
	precision  = 14
	registers  = 1 << precision
)

// Summary est la forme transmise d'un ensemble d'IP : la liste exacte, ou le sketch quand elle est trop longue.
type Summary struct {
	Exact []string `json:"exact,omitempty"`
	HLL   string   `json:"hll,omitempty"` // registres, base64
}

// Set accumule des IP. Le zéro n'est pas utilisable : passer par New.
type Set struct {
	exact map[string]struct{}
	regs  []uint8 // non nil dès que l'ensemble est un sketch
}

// New rend un ensemble vide.
func New() *Set { return &Set{exact: map[string]struct{}{}} }

// hash : FNV-1a de l'IP, brassé pour répartir les bits (le sketch lit les bits hauts et compte les zéros bas).
func hash(s string) uint64 {
	h := fnv.New64a()
	_, _ = h.Write([]byte(s))
	x := h.Sum64()
	x ^= x >> 30
	x *= 0xbf58476d1ce4e5b9
	x ^= x >> 27
	x *= 0x94d049bb133111eb
	x ^= x >> 31
	return x
}

func (s *Set) addHash(h uint64) {
	idx := h >> (64 - precision)
	rank := uint8(bits.LeadingZeros64(h<<precision|1<<(precision-1))) + 1
	if rank > s.regs[idx] {
		s.regs[idx] = rank
	}
}

// toSketch convertit l'ensemble exact en sketch.
func (s *Set) toSketch() {
	if s.regs != nil {
		return
	}
	s.regs = make([]uint8, registers)
	for ip := range s.exact {
		s.addHash(hash(ip))
	}
	s.exact = nil
}

// Add ajoute une IP.
func (s *Set) Add(ip string) {
	if ip == "" {
		return
	}
	if s.regs != nil {
		s.addHash(hash(ip))
		return
	}
	s.exact[ip] = struct{}{}
	if len(s.exact) > ExactLimit {
		s.toSketch()
	}
}

// Merge ajoute le contenu d'un résumé reçu d'une autre source.
func (s *Set) Merge(o Summary) error {
	if o.HLL != "" {
		raw, err := base64.StdEncoding.DecodeString(o.HLL)
		if err != nil || len(raw) != registers {
			return errors.New("ipsketch: résumé illisible")
		}
		s.toSketch()
		for i, r := range raw {
			if r > s.regs[i] {
				s.regs[i] = r
			}
		}
	}
	for _, ip := range o.Exact {
		s.Add(ip)
	}
	return nil
}

// Exact dit si le compte est exact.
func (s *Set) Exact() bool { return s.regs == nil }

// Count rend le nombre d'IP distinctes : exact tant que Exact() est vrai, estimé sinon.
func (s *Set) Count() int64 {
	if s.regs == nil {
		return int64(len(s.exact))
	}
	m := float64(registers)
	var sum float64
	zeros := 0
	for _, r := range s.regs {
		sum += math.Pow(2, -float64(r))
		if r == 0 {
			zeros++
		}
	}
	est := 0.7213 / (1 + 1.079/m) * m * m / sum
	if est <= 2.5*m && zeros > 0 {
		est = m * math.Log(m/float64(zeros))
	}
	return int64(est + 0.5)
}

// Summary rend la forme transmissible.
func (s *Set) Summary() Summary {
	if s.regs != nil {
		return Summary{HLL: base64.StdEncoding.EncodeToString(s.regs)}
	}
	out := make([]string, 0, len(s.exact))
	for ip := range s.exact {
		out = append(out, ip)
	}
	return Summary{Exact: out}
}
