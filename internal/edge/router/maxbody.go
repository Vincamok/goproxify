// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

// DefaultMaxBodySize est la limite du corps de requête client quand max_body_size n'est pas défini.
const DefaultMaxBodySize int64 = 100 << 20

// EffectiveMaxBodySize retourne la limite appliquée au corps client : 0 = défaut, valeur négative = illimité (retourne 0).
func (r *Route) EffectiveMaxBodySize() int64 {
	switch {
	case r.MaxBodySize < 0:
		return 0
	case r.MaxBodySize == 0:
		return DefaultMaxBodySize
	}
	return r.MaxBodySize
}
