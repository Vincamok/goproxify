// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package routesecrets masque les secrets de la configuration d'une route dans tout ce que l'Admin renvoie
// (API, MCP, export, historique) et les rétablit quand un client renvoie le masque. La configuration d'une route
// est un JSON libre dont les champs évoluent : les secrets sont repérés par le nom de leur clé, à n'importe quelle
// profondeur, plutôt que par une liste de chemins qu'un nouveau champ rendrait incomplète.
package routesecrets

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"strings"

	"github.com/vincamok/goproxify/internal/modules"
)

// secretKeys : champs de secret des structures de route (router.Route) et en-têtes qui portent un identifiant.
var secretKeys = map[string]bool{
	"client_secret": true, "session_secret": true, "bind_password": true, "challenge_secret": true,
	"challenge_provider_secret": true, "key_pem": true, "secret": true, "password": true, "bypass_header": true,
	"authorization": true, "proxy-authorization": true, "x-api-key": true,
}

// PluginManifests donne le manifeste d'un plugin pour masquer les champs secrets de sa configuration.
type PluginManifests func(name string) (modules.Manifest, bool)

func isSecretKey(k string) bool { return secretKeys[strings.ToLower(k)] }

func present(v any) bool {
	s, ok := v.(string)
	return ok && s != ""
}

// Mask remplace chaque secret renseigné par le masque. Une valeur illisible est renvoyée telle quelle.
func Mask(raw []byte, plugins PluginManifests) []byte {
	var v any
	if json.Unmarshal(raw, &v) != nil {
		return raw
	}
	maskValue(v)
	if m, ok := v.(map[string]any); ok && plugins != nil {
		maskPlugins(m, plugins)
	}
	out, err := json.Marshal(v)
	if err != nil {
		return raw
	}
	return out
}

func maskValue(v any) {
	switch x := v.(type) {
	case map[string]any:
		for k, e := range x {
			if isSecretKey(k) && present(e) {
				x[k] = modules.Masque
				continue
			}
			maskValue(e)
		}
	case []any:
		for _, e := range x {
			maskValue(e)
		}
	}
}

func maskPlugins(route map[string]any, plugins PluginManifests) {
	list, _ := route["plugins"].([]any)
	for _, e := range list {
		p, _ := e.(map[string]any)
		name, _ := p["name"].(string)
		cfg, _ := p["config"].(map[string]any)
		if man, ok := plugins(name); ok && cfg != nil {
			p["config"] = man.Mask(cfg)
		}
	}
}

// Keep reprend dans la nouvelle configuration les secrets de l'ancienne quand elle renvoie le masque (un client
// qui relit une route puis la renvoie telle quelle). Un masque sans valeur d'origine — route créée avec le
// masque, secret d'un utilisateur renommé ou déplacé — est signalé dans `missing` : il ne doit jamais être
// enregistré comme valeur. Les éléments d'une liste d'objets sont appariés par `username` quand il existe.
func Keep(oldRaw, nextRaw []byte, plugins PluginManifests) (out []byte, missing []string) {
	var old, next any
	if json.Unmarshal(nextRaw, &next) != nil {
		return nextRaw, nil
	}
	if len(oldRaw) > 0 {
		_ = json.Unmarshal(oldRaw, &old)
	}
	keepValue("", old, next, &missing)
	if m, ok := next.(map[string]any); ok && plugins != nil {
		keepPlugins(m, old, plugins, &missing)
	}
	b, err := json.Marshal(next)
	if err != nil {
		return nextRaw, missing
	}
	return b, missing
}

func keepValue(path string, old, next any, missing *[]string) {
	switch n := next.(type) {
	case map[string]any:
		o, _ := old.(map[string]any)
		for k, e := range n {
			p := path + "." + k
			if isSecretKey(k) {
				if s, ok := e.(string); ok && s == modules.Masque {
					if prev, ok := o[k].(string); ok && prev != "" && prev != modules.Masque {
						n[k] = prev
					} else {
						delete(n, k)
						*missing = append(*missing, strings.TrimPrefix(p, "."))
					}
				}
				continue
			}
			keepValue(p, o[k], e, missing)
		}
	case []any:
		o, _ := old.([]any)
		for i, e := range n {
			keepValue(fmt.Sprintf("%s[%d]", path, i), pair(o, n, i), e, missing)
		}
	}
}

// pair retrouve l'ancien élément d'une liste : même `username` si l'élément en porte un, sinon même position.
func pair(old, next []any, i int) any {
	if item, ok := next[i].(map[string]any); ok {
		if u, ok := item["username"].(string); ok && u != "" {
			for _, e := range old {
				if o, ok := e.(map[string]any); ok && o["username"] == u {
					return o
				}
			}
			return nil
		}
	}
	if i < len(old) {
		return old[i]
	}
	return nil
}

func keepPlugins(next map[string]any, old any, plugins PluginManifests, missing *[]string) {
	oldRoute, _ := old.(map[string]any)
	oldList, _ := oldRoute["plugins"].([]any)
	list, _ := next["plugins"].([]any)
	for _, e := range list {
		p, _ := e.(map[string]any)
		name, _ := p["name"].(string)
		cfg, _ := p["config"].(map[string]any)
		man, ok := plugins(name)
		if !ok || cfg == nil {
			continue
		}
		var oldCfg map[string]any
		for _, oe := range oldList {
			if op, _ := oe.(map[string]any); op != nil && op["name"] == name {
				oldCfg, _ = op["config"].(map[string]any)
			}
		}
		for _, f := range man.Fields {
			if !f.Secret {
				continue
			}
			if v, _ := lookup(cfg, f.Key).(string); v == modules.Masque && lookup(oldCfg, f.Key) == nil {
				*missing = append(*missing, "plugins."+name+"."+f.Key)
			}
		}
		p["config"] = man.KeepSecrets(oldCfg, cfg)
	}
}

func lookup(m map[string]any, path string) any {
	var cur any = m
	for _, k := range strings.Split(path, ".") {
		mm, ok := cur.(map[string]any)
		if !ok {
			return nil
		}
		cur = mm[k]
	}
	return cur
}

// FromDB lit le manifeste d'un plugin installé pour savoir quels champs de sa configuration sont secrets.
func FromDB(db *sql.DB) PluginManifests {
	return func(name string) (modules.Manifest, bool) {
		if db == nil || name == "" {
			return modules.Manifest{}, false
		}
		var raw string
		if db.QueryRow(`SELECT manifest FROM plugins WHERE name=?`, name).Scan(&raw) != nil {
			return modules.Manifest{}, false
		}
		var m struct {
			Fields []modules.Field `json:"fields"`
		}
		if json.Unmarshal([]byte(raw), &m) != nil {
			return modules.Manifest{}, false
		}
		return modules.Manifest{Type: name, Fields: m.Fields}, true
	}
}
