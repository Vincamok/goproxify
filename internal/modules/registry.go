// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package modules fournit le registre commun des familles de modules (canaux de notification,
// puis fournisseurs d'authentification, détecteurs, sources de découverte…). Un module déclare un
// manifeste — type, libellé, champs de configuration — et une fabrique ; le manifeste est la
// source unique pour valider la configuration, masquer les secrets et générer les formulaires.
package modules

import (
	"fmt"
	"sort"
	"strings"
	"sync"
)

// Genres de champ d'un manifeste.
const (
	KindText     = "text"
	KindPassword = "password"
	KindNumber   = "number"
	KindList     = "list"
	KindBool     = "bool"
)

// Masque est la valeur affichée à la place d'un secret.
const Masque = "••••••••"

// Field décrit un champ de configuration.
type Field struct {
	Key         string `json:"key"`
	Label       string `json:"label"`
	Placeholder string `json:"placeholder,omitempty"`
	Kind        string `json:"kind"`
	// Secret : jamais renvoyé par l'API (remplacé par Masque) et conservé quand une
	// modification ne le renseigne pas.
	Secret   bool `json:"secret,omitempty"`
	Required bool `json:"required,omitempty"`
	// Multiline : champ saisi sur plusieurs lignes (clé PEM, script) ; l'interface affiche une zone de texte.
	Multiline bool `json:"multiline,omitempty"`
	// Env : variable d'environnement qui fournit la valeur par défaut du champ (repli quand la
	// configuration saisie ne le renseigne pas). Optionnel.
	Env string `json:"env,omitempty"`
}

// Manifest décrit un module.
type Manifest struct {
	Type   string  `json:"type"`
	Label  string  `json:"label"`
	Fields []Field `json:"fields"`
	// Attrs porte les métadonnées propres à une famille (extensions de fichier d'un importeur,
	// indication d'affichage…). Libre, sérialisé tel quel ; ni validé ni interprété par le registre.
	Attrs map[string]any `json:"attrs,omitempty"`
}

// Strings lit un attribut de type liste de chaînes (absent ou d'un autre type : nil).
func (m Manifest) Strings(key string) []string {
	switch v := m.Attrs[key].(type) {
	case []string:
		return v
	case []any:
		var out []string
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	}
	return nil
}

// String lit un attribut de type chaîne.
func (m Manifest) String(key string) string {
	s, _ := m.Attrs[key].(string)
	return s
}

// Registry range les modules d'une famille. T est le type de la fabrique.
type Registry[T any] struct {
	mu    sync.RWMutex
	order []string
	items map[string]entry[T]
}

type entry[T any] struct {
	manifest Manifest
	factory  T
}

func NewRegistry[T any]() *Registry[T] {
	return &Registry[T]{items: map[string]entry[T]{}}
}

// Register ajoute un module. Un manifeste invalide ou un type en double est une erreur de
// programmation : Register panique, pour être vu au démarrage et dans les tests.
func (r *Registry[T]) Register(m Manifest, factory T) {
	if err := m.check(); err != nil {
		panic("modules: " + err.Error())
	}
	if m.Fields == nil {
		m.Fields = []Field{} // JSON : [] et non null
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if _, dup := r.items[m.Type]; dup {
		panic(fmt.Sprintf("modules: type %q déjà enregistré", m.Type))
	}
	r.items[m.Type] = entry[T]{manifest: m, factory: factory}
	r.order = append(r.order, m.Type)
}

// Lookup retourne la fabrique et le manifeste d'un type.
func (r *Registry[T]) Lookup(typ string) (T, Manifest, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	e, ok := r.items[typ]
	return e.factory, e.manifest, ok
}

// Manifests retourne les manifestes dans l'ordre d'enregistrement.
func (r *Registry[T]) Manifests() []Manifest {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := make([]Manifest, 0, len(r.order))
	for _, t := range r.order {
		out = append(out, r.items[t].manifest)
	}
	return out
}

// Types retourne les types triés alphabétiquement.
func (r *Registry[T]) Types() []string {
	r.mu.RLock()
	defer r.mu.RUnlock()
	out := append([]string(nil), r.order...)
	sort.Strings(out)
	return out
}

func (m Manifest) check() error {
	if m.Type == "" || m.Label == "" {
		return fmt.Errorf("manifeste sans type ou libellé")
	}
	seen := map[string]bool{}
	for _, f := range m.Fields {
		if f.Key == "" || f.Label == "" {
			return fmt.Errorf("%s : champ sans clé ou libellé", m.Type)
		}
		if seen[f.Key] {
			return fmt.Errorf("%s : champ %q en double", m.Type, f.Key)
		}
		seen[f.Key] = true
		switch f.Kind {
		case KindText, KindPassword, KindNumber, KindList, KindBool:
		default:
			return fmt.Errorf("%s : champ %q de genre inconnu %q", m.Type, f.Key, f.Kind)
		}
		if f.Secret && f.Kind != KindPassword {
			return fmt.Errorf("%s : le champ secret %q doit être de genre password", m.Type, f.Key)
		}
	}
	return nil
}

func (m Manifest) field(key string) (Field, bool) {
	for _, f := range m.Fields {
		if f.Key == key {
			return f, true
		}
	}
	return Field{}, false
}

// Validate vérifie une configuration saisie : champs requis présents et non vides, clés
// inconnues refusées. À appeler à la création et à la modification ; une configuration déjà
// stockée n'est jamais revalidée.
func (m Manifest) Validate(cfg map[string]any) error {
	var missing []string
	for _, f := range m.Fields {
		if f.Required && empty(cfg[f.Key]) {
			missing = append(missing, f.Key)
		}
	}
	if len(missing) > 0 {
		return fmt.Errorf("champs requis manquants : %s", strings.Join(missing, ", "))
	}
	var unknown []string
	for k := range cfg {
		if _, ok := m.field(k); !ok {
			unknown = append(unknown, k)
		}
	}
	if len(unknown) > 0 {
		sort.Strings(unknown)
		return fmt.Errorf("champs inconnus : %s", strings.Join(unknown, ", "))
	}
	return nil
}

// Mask remplace chaque secret renseigné par Masque.
func (m Manifest) Mask(cfg map[string]any) map[string]any {
	out := make(map[string]any, len(cfg))
	for k, v := range cfg {
		if f, ok := m.field(k); ok && f.Secret && !empty(v) {
			out[k] = Masque
		} else {
			out[k] = v
		}
	}
	return out
}

// KeepSecrets complète une nouvelle configuration avec les secrets de l'ancienne quand elle ne
// les renseigne pas (absents, vides ou égaux au masque). Un secret ne s'efface donc pas en
// modifiant le reste du canal.
func (m Manifest) KeepSecrets(old, next map[string]any) map[string]any {
	out := make(map[string]any, len(next))
	for k, v := range next {
		out[k] = v
	}
	for _, f := range m.Fields {
		if !f.Secret {
			continue
		}
		if v, ok := out[f.Key]; ok && !empty(v) && v != Masque {
			continue
		}
		if prev, ok := old[f.Key]; ok && !empty(prev) {
			out[f.Key] = prev
		} else {
			delete(out, f.Key)
		}
	}
	return out
}

func empty(v any) bool {
	switch t := v.(type) {
	case nil:
		return true
	case string:
		return strings.TrimSpace(t) == ""
	case []any:
		return len(t) == 0
	case []string:
		return len(t) == 0
	}
	return false
}
