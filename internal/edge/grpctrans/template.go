// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package grpctrans expose un backend gRPC unaire en REST/JSON : les annotations google.api.http
// des descripteurs protobuf décrivent les routes, la passerelle traduit requêtes et réponses.
package grpctrans

import (
	"fmt"
	"net/url"
	"strings"
)

type elemKind int

const (
	elemLiteral elemKind = iota
	elemStar             // « * » : un segment
	elemDoubleStar       // « ** » : zéro segment ou plus
)

type pathElem struct {
	kind elemKind
	lit  string
}

// pathVar lie un champ de la requête aux éléments [start, end) du gabarit qu'il capture.
type pathVar struct {
	field      string
	start, end int
}

// template est un gabarit de chemin google.api.http : /v1/{name=projects/*}/items/{id}:verbe
type template struct {
	elems []pathElem
	vars  []pathVar
	verb  string
}

// splitTopLevel coupe s sur sep en ignorant ce qui est entre accolades.
func splitTopLevel(s string, sep byte) []string {
	var out []string
	depth, last := 0, 0
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '{':
			depth++
		case '}':
			depth--
		case sep:
			if depth == 0 {
				out = append(out, s[last:i])
				last = i + 1
			}
		}
	}
	return append(out, s[last:])
}

func parseTemplate(s string) (*template, error) {
	if !strings.HasPrefix(s, "/") {
		return nil, fmt.Errorf("le gabarit %q doit commencer par /", s)
	}
	t := &template{}
	body := s[1:]
	// Le verbe suit le dernier segment : « :verbe » hors accolades.
	segs := splitTopLevel(body, '/')
	if last := segs[len(segs)-1]; last != "" {
		if parts := splitTopLevel(last, ':'); len(parts) == 2 {
			segs[len(segs)-1] = parts[0]
			t.verb = parts[1]
			if t.verb == "" {
				return nil, fmt.Errorf("le gabarit %q a un verbe vide", s)
			}
		} else if len(parts) > 2 {
			return nil, fmt.Errorf("le gabarit %q a plusieurs verbes", s)
		}
	}
	for _, seg := range segs {
		switch {
		case seg == "":
			return nil, fmt.Errorf("le gabarit %q a un segment vide", s)
		case strings.HasPrefix(seg, "{"):
			if !strings.HasSuffix(seg, "}") {
				return nil, fmt.Errorf("le gabarit %q : variable non fermée dans %q", s, seg)
			}
			inner := seg[1 : len(seg)-1]
			field, pattern, hasPattern := strings.Cut(inner, "=")
			if field == "" {
				return nil, fmt.Errorf("le gabarit %q : variable sans nom", s)
			}
			if !hasPattern {
				pattern = "*"
			}
			start := len(t.elems)
			for _, p := range strings.Split(pattern, "/") {
				switch p {
				case "*":
					t.elems = append(t.elems, pathElem{kind: elemStar})
				case "**":
					t.elems = append(t.elems, pathElem{kind: elemDoubleStar})
				case "":
					return nil, fmt.Errorf("le gabarit %q : motif vide dans %q", s, seg)
				default:
					if strings.ContainsAny(p, "{}") {
						return nil, fmt.Errorf("le gabarit %q : variables imbriquées non permises", s)
					}
					t.elems = append(t.elems, pathElem{kind: elemLiteral, lit: p})
				}
			}
			t.vars = append(t.vars, pathVar{field: field, start: start, end: len(t.elems)})
		case seg == "*":
			t.elems = append(t.elems, pathElem{kind: elemStar})
		case seg == "**":
			t.elems = append(t.elems, pathElem{kind: elemDoubleStar})
		default:
			if strings.ContainsAny(seg, "{}") {
				return nil, fmt.Errorf("le gabarit %q : accolades mal placées dans %q", s, seg)
			}
			t.elems = append(t.elems, pathElem{kind: elemLiteral, lit: seg})
		}
	}
	return t, nil
}

// literals compte les segments littéraux : un gabarit qui en a davantage est plus précis.
func (t *template) literals() int {
	n := 0
	for _, e := range t.elems {
		if e.kind == elemLiteral {
			n++
		}
	}
	return n
}

// match compare le chemin (déjà privé de son préfixe de serveur) au gabarit et retourne les
// valeurs des variables. escaped est le chemin encodé : les segments sont décodés un par un, pour
// qu'un « %2F » reste dans son segment.
func (t *template) match(escaped string) (map[string]string, bool) {
	p := escaped
	if t.verb != "" {
		var ok bool
		if p, ok = strings.CutSuffix(p, ":"+t.verb); !ok {
			return nil, false
		}
	}
	if !strings.HasPrefix(p, "/") {
		return nil, false
	}
	raw := strings.Split(p[1:], "/")
	segs := make([]string, len(raw))
	for i, s := range raw {
		d, err := url.PathUnescape(s)
		if err != nil {
			return nil, false
		}
		segs[i] = d
	}
	spans := make([][2]int, len(t.elems))
	if !t.matchFrom(0, 0, segs, spans) {
		return nil, false
	}
	vars := make(map[string]string, len(t.vars))
	for _, v := range t.vars {
		var parts []string
		for i := v.start; i < v.end; i++ {
			parts = append(parts, segs[spans[i][0]:spans[i][1]]...)
		}
		vars[v.field] = strings.Join(parts, "/")
	}
	return vars, true
}

// matchFrom fait correspondre elems[ei:] à segs[si:] avec retour arrière pour « ** ».
func (t *template) matchFrom(ei, si int, segs []string, spans [][2]int) bool {
	if ei == len(t.elems) {
		return si == len(segs)
	}
	switch e := t.elems[ei]; e.kind {
	case elemLiteral:
		if si >= len(segs) || segs[si] != e.lit {
			return false
		}
		spans[ei] = [2]int{si, si + 1}
		return t.matchFrom(ei+1, si+1, segs, spans)
	case elemStar:
		if si >= len(segs) || segs[si] == "" {
			return false
		}
		spans[ei] = [2]int{si, si + 1}
		return t.matchFrom(ei+1, si+1, segs, spans)
	default: // **
		for end := len(segs); end >= si; end-- {
			spans[ei] = [2]int{si, end}
			if t.matchFrom(ei+1, end, segs, spans) {
				return true
			}
		}
		return false
	}
}
