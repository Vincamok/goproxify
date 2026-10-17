// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import (
	"encoding/json"
	"strings"
)

// UnmarshalJSON accepte aussi `aliases` sous forme de chaîne (« a.fr, b.fr » ou « a.fr;b.fr »),
// saisie courante dans l'éditeur YAML ou issue d'un export CSV, en plus de la liste canonique.
func (r *Route) UnmarshalJSON(data []byte) error {
	type plain Route
	aux := struct {
		*plain
		Aliases json.RawMessage `json:"aliases"`
	}{plain: (*plain)(r)}
	if err := json.Unmarshal(data, &aux); err != nil {
		return err
	}
	if len(aux.Aliases) == 0 {
		return nil
	}
	var list []string
	if err := json.Unmarshal(aux.Aliases, &list); err != nil {
		var s string
		if err := json.Unmarshal(aux.Aliases, &s); err != nil {
			return err
		}
		list = strings.FieldsFunc(s, func(c rune) bool { return c == ',' || c == ';' || c == ' ' || c == '\n' || c == '\t' })
	}
	r.Aliases = list
	return nil
}
