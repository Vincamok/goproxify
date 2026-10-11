// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"encoding/json"
	"fmt"
	"regexp"
	"strings"
)

// Variables : « {{detail.ip}} », « {{steps.s2.status}} », « {{flow.name}} », « {{run.id}} » à l'exécution ;
// « {{param.x}} » à l'installation d'un modèle. Une simple substitution suffit : pas de logique dans les
// variables, la logique vit dans les étapes.
var varRe = regexp.MustCompile(`\{\{\s*([A-Za-z0-9_]+(?:\.[A-Za-z0-9_-]+)*)\s*\}\}`)

// runtimeRoots sont les racines résolues pendant une exécution.
var runtimeRoots = map[string]bool{"detail": true, "steps": true, "flow": true, "run": true}

// resolve remplace les variables de v (chaînes, objets et listes imbriqués) par leur valeur dans scope.
// Une chaîne réduite à une variable prend le type de la valeur (nombre, booléen, objet) ; une variable
// insérée dans un texte y est écrite. Une variable dont la racine n'est pas dans scope reste telle quelle,
// une variable absente devient vide.
func resolve(v any, scope map[string]any) any {
	switch t := v.(type) {
	case string:
		return resolveString(t, scope)
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = resolve(e, scope)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = resolve(e, scope)
		}
		return out
	}
	return v
}

func resolveMap(m map[string]any, scope map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return resolve(m, scope).(map[string]any)
}

func resolveString(s string, scope map[string]any) any {
	if !strings.Contains(s, "{{") {
		return s
	}
	if m := varRe.FindStringSubmatch(s); m != nil && m[0] == strings.TrimSpace(s) {
		if v, known := lookupVar(m[1], scope); known {
			return v
		}
		return s
	}
	return varRe.ReplaceAllStringFunc(s, func(match string) string {
		path := varRe.FindStringSubmatch(match)[1]
		v, known := lookupVar(path, scope)
		if !known {
			return match
		}
		return text(v)
	})
}

// lookupVar lit path dans scope. known est faux si la racine n'est pas dans scope (variable laissée telle quelle).
func lookupVar(path string, scope map[string]any) (any, bool) {
	segs := strings.Split(path, ".")
	cur, ok := scope[segs[0]]
	if !ok {
		return nil, false
	}
	for _, seg := range segs[1:] {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, true
		}
		cur = m[seg]
	}
	return cur, true
}

func text(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return fmt.Sprintf("%d", int64(t))
		}
		return fmt.Sprintf("%g", t)
	case map[string]any, []any:
		b, _ := json.Marshal(t)
		return string(b)
	}
	return fmt.Sprint(v)
}

// varsIn liste les variables (chemins) utilisées dans v.
func varsIn(v any) []string {
	var out []string
	var walk func(any)
	walk = func(v any) {
		switch t := v.(type) {
		case string:
			for _, m := range varRe.FindAllStringSubmatch(t, -1) {
				out = append(out, m[1])
			}
		case map[string]any:
			for _, e := range t {
				walk(e)
			}
		case []any:
			for _, e := range t {
				walk(e)
			}
		}
	}
	walk(v)
	return out
}

// runScope construit les variables d'une exécution.
func runScope(run *Run) map[string]any {
	steps := map[string]any{}
	for id, out := range run.Context.Steps {
		steps[id] = map[string]any(out)
	}
	detail := run.Context.Detail
	if detail == nil {
		detail = map[string]any{}
	}
	return map[string]any{
		"detail": detail,
		"steps":  steps,
		"flow":   map[string]any{"id": run.FlowID, "name": run.FlowName},
		"run":    map[string]any{"id": run.ID},
	}
}

// normalizeJSON fait passer v par JSON : les nombres deviennent float64 et les structures des maps, comme
// à la lecture d'une requête. Les variables et les manifestes travaillent sur cette forme.
func normalizeJSON(v any) map[string]any {
	b, _ := json.Marshal(v)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	if out == nil {
		out = map[string]any{}
	}
	return out
}
