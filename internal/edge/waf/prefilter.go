// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"regexp/syntax"
	"strings"
)

// DefaultMaxBodyBytes est la taille de corps inspectée quand la route ne fixe pas max_body_mb. Le coût d'une
// inspection croît avec le corps (environ 1,4 µs par octet pour les règles par défaut : 1 Mio ≈ 1,5 s de CPU) : le
// défaut de 10 Mio laissait un client non authentifié occuper un cœur plusieurs secondes par requête.
const DefaultMaxBodyBytes = 128 << 10

// Le moteur d'expressions régulières de Go parcourt une valeur octet par octet, surtout pour les motifs insensibles
// à la casse à nombreuses alternatives, ce qui domine le coût d'une inspection. Presque toujours, une valeur ne
// contient rien qui ressemble à une attaque : on sait alors, avec une simple recherche de sous-chaîne, qu'aucune règle
// ne peut s'appliquer. requiredLiterals extrait de chaque motif des sous-chaînes dont l'une au moins doit figurer
// dans tout texte qu'il reconnaît ; le motif n'est évalué que si la valeur (passée en minuscules) en contient une.
//
// Le pré-filtre ne fait que dispenser d'une évaluation : il ne change jamais le résultat. Dans le doute (motif sans
// littéral exploitable, caractère non ASCII dans un littéral), il n'y a pas de pré-filtre.

// withPrefilters calcule le pré-filtre de chaque règle.
func withPrefilters(rules []Rule) []Rule {
	for i := range rules {
		if rules[i].Pattern != nil {
			rules[i].required = requiredLiterals(rules[i].Pattern.String())
		}
	}
	return rules
}

// requiredLiterals retourne les sous-chaînes minuscules dont une figure dans tout texte reconnu par le motif, ou nil.
func requiredLiterals(pattern string) []string {
	re, err := syntax.Parse(pattern, syntax.Perl)
	if err != nil {
		return nil
	}
	set, ok := literalsOf(re)
	if !ok || len(set) == 0 {
		return nil
	}
	return dedupe(set)
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	out := in[:0:0]
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}

// minLen : longueur de la plus courte sous-chaîne d'un ensemble (plus elle est grande, plus le pré-filtre écarte).
func minLen(set []string) int {
	m := 1 << 30
	for _, s := range set {
		if len(s) < m {
			m = len(s)
		}
	}
	return m
}

// literalsOf retourne un ensemble de sous-chaînes minuscules dont l'une est présente dans tout texte reconnu par re.
func literalsOf(re *syntax.Regexp) ([]string, bool) {
	switch re.Op {
	case syntax.OpLiteral:
		var b strings.Builder
		for _, r := range re.Rune {
			if r >= 0x80 {
				return nil, false
			}
			if r >= 'A' && r <= 'Z' {
				r += 'a' - 'A'
			}
			b.WriteRune(r)
		}
		if b.Len() == 0 {
			return nil, false
		}
		return []string{b.String()}, true
	case syntax.OpCapture:
		return literalsOf(re.Sub[0])
	case syntax.OpPlus:
		return literalsOf(re.Sub[0])
	case syntax.OpRepeat:
		if re.Min >= 1 {
			return literalsOf(re.Sub[0])
		}
		return nil, false
	case syntax.OpConcat:
		// Tout enfant est obligatoire : on garde l'ensemble le plus sélectif (sous-chaînes les plus longues).
		var best []string
		for _, sub := range re.Sub {
			if set, ok := literalsOf(sub); ok && (best == nil || minLen(set) > minLen(best)) {
				best = set
			}
		}
		return best, best != nil
	case syntax.OpAlternate:
		// Une des branches s'applique : il faut un littéral pour chacune.
		var all []string
		for _, sub := range re.Sub {
			set, ok := literalsOf(sub)
			if !ok {
				return nil, false
			}
			all = append(all, set...)
		}
		return all, true
	}
	return nil, false
}

// foldSensitive : les seuls caractères non ASCII que la comparaison insensible à la casse de Go confond avec une
// lettre ASCII (ſ avec s, K Kelvin avec k). Une valeur qui en contient peut correspondre à un littéral sans le
// contenir : elle n'est pas pré-filtrée.
var foldSensitive = []string{"\u017f", "\u212a"}

// lowered retourne la valeur en minuscules pour le pré-filtre, ou "" et false si elle ne peut pas être pré-filtrée.
func lowered(val string) (string, bool) {
	for _, f := range foldSensitive {
		if strings.Contains(val, f) {
			return "", false
		}
	}
	return strings.ToLower(val), true
}

// mayMatch indique si la règle peut s'appliquer à la valeur dont lower est la forme minuscule (ok=false : inconnu).
func (r *Rule) mayMatch(lower string, ok bool) bool {
	if r.required == nil || !ok {
		return true
	}
	for _, lit := range r.required {
		if strings.Contains(lower, lit) {
			return true
		}
	}
	return false
}
