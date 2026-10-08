// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package modules

import (
	"fmt"
	"sort"
	"strings"
)

// Les opérations ci-dessous travaillent sur une configuration JSON (map[string]any). Une clé de champ
// qui contient un point désigne un champ imbriqué : « oidc.client_secret » est la clé client_secret de
// l'objet oidc. Une clé sans point est un champ de premier niveau, comme avant.

func getPath(cfg map[string]any, path string) (any, bool) {
	var cur any = cfg
	for _, seg := range strings.Split(path, ".") {
		m, ok := cur.(map[string]any)
		if !ok {
			return nil, false
		}
		if cur, ok = m[seg]; !ok {
			return nil, false
		}
	}
	return cur, true
}

// setPath pose v à path en créant les objets intermédiaires manquants.
func setPath(cfg map[string]any, path string, v any) {
	segs := strings.Split(path, ".")
	cur := cfg
	for _, seg := range segs[:len(segs)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			next = map[string]any{}
			cur[seg] = next
		}
		cur = next
	}
	cur[segs[len(segs)-1]] = v
}

// delPath retire path ; un objet intermédiaire devenu vide est retiré aussi.
func delPath(cfg map[string]any, path string) {
	segs := strings.Split(path, ".")
	var chain []map[string]any
	cur := cfg
	for _, seg := range segs[:len(segs)-1] {
		next, ok := cur[seg].(map[string]any)
		if !ok {
			return
		}
		chain = append(chain, cur)
		cur = next
	}
	delete(cur, segs[len(segs)-1])
	for i := len(chain) - 1; i >= 0; i-- {
		if len(cur) > 0 {
			return
		}
		delete(chain[i], segs[i])
		cur = chain[i]
	}
}

// clone copie en profondeur objets et listes : les opérations ne modifient jamais leur entrée.
func clone(v any) any {
	switch t := v.(type) {
	case map[string]any:
		out := make(map[string]any, len(t))
		for k, e := range t {
			out[k] = clone(e)
		}
		return out
	case []any:
		out := make([]any, len(t))
		for i, e := range t {
			out[i] = clone(e)
		}
		return out
	}
	return v
}

func cloneMap(m map[string]any) map[string]any {
	if m == nil {
		return map[string]any{}
	}
	return clone(m).(map[string]any)
}

// Validate vérifie une configuration saisie : champs requis présents et non vides, clés
// inconnues refusées (au premier niveau comme dans les objets imbriqués). À appeler à la création
// et à la modification ; une configuration déjà stockée n'est jamais revalidée.
func (m Manifest) Validate(cfg map[string]any) error {
	var missing []string
	for _, f := range m.Fields {
		if !f.Required {
			continue
		}
		if v, _ := getPath(cfg, f.Key); empty(v) {
			missing = append(missing, f.Key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("champs requis manquants : %s", strings.Join(missing, ", "))
	}
	var unknown []string
	m.walkUnknown("", cfg, &unknown)
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("champs inconnus : %s", strings.Join(unknown, ", "))
	}
	return nil
}

// walkUnknown liste les chemins de cfg qu'aucun champ du manifeste ne déclare. Un objet est exploré
// seulement si un champ déclaré se trouve en dessous ; un champ déclaré est une feuille.
func (m Manifest) walkUnknown(prefix string, cfg map[string]any, out *[]string) {
	for k, v := range cfg {
		p := prefix + k
		if m.declared(p) {
			continue
		}
		if sub, ok := v.(map[string]any); ok && m.hasBelow(p+".") {
			m.walkUnknown(p+".", sub, out)
			continue
		}
		*out = append(*out, p)
	}
}

func (m Manifest) declared(path string) bool {
	for _, f := range m.Fields {
		if f.Key == path {
			return true
		}
	}
	return false
}

func (m Manifest) hasBelow(prefix string) bool {
	for _, f := range m.Fields {
		if strings.HasPrefix(f.Key, prefix) {
			return true
		}
	}
	return false
}

// Mask remplace chaque secret renseigné par Masque (y compris les secrets des éléments d'une liste).
func (m Manifest) Mask(cfg map[string]any) map[string]any {
	out := cloneMap(cfg)
	for _, f := range m.Fields {
		v, ok := getPath(out, f.Key)
		if !ok {
			continue
		}
		if f.Secret && !empty(v) {
			setPath(out, f.Key, Masque)
		}
		if f.ItemSecret != "" {
			list, _ := v.([]any)
			for _, e := range list {
				if item, ok := e.(map[string]any); ok && !empty(item[f.ItemSecret]) {
					item[f.ItemSecret] = Masque
				}
			}
		}
	}
	return out
}

// KeepSecrets complète une nouvelle configuration avec les secrets de l'ancienne quand elle ne
// les renseigne pas (absents, vides ou égaux au masque). Un secret ne s'efface donc pas en
// modifiant le reste de la configuration. Pour une liste d'objets, le secret d'un élément est repris
// de l'élément de même ItemKey.
func (m Manifest) KeepSecrets(old, next map[string]any) map[string]any {
	out := cloneMap(next)
	for _, f := range m.Fields {
		if f.Secret {
			if v, ok := getPath(out, f.Key); ok && !empty(v) && v != Masque {
				continue
			}
			if prev, ok := getPath(old, f.Key); ok && !empty(prev) {
				setPath(out, f.Key, prev)
			} else {
				delPath(out, f.Key)
			}
		}
		if f.ItemSecret != "" {
			m.keepItemSecrets(f, old, out)
		}
	}
	return out
}

func (m Manifest) keepItemSecrets(f Field, old, out map[string]any) {
	v, _ := getPath(out, f.Key)
	list, _ := v.([]any)
	oldV, _ := getPath(old, f.Key)
	oldList, _ := oldV.([]any)
	prev := map[string]any{}
	for _, e := range oldList {
		if item, ok := e.(map[string]any); ok {
			if id, _ := item[f.ItemKey].(string); id != "" && !empty(item[f.ItemSecret]) {
				prev[id] = item[f.ItemSecret]
			}
		}
	}
	for _, e := range list {
		item, ok := e.(map[string]any)
		if !ok {
			continue
		}
		if s := item[f.ItemSecret]; !empty(s) && s != Masque {
			continue
		}
		if id, _ := item[f.ItemKey].(string); id != "" {
			if p, ok := prev[id]; ok {
				item[f.ItemSecret] = p
				continue
			}
		}
		delete(item, f.ItemSecret)
	}
}
