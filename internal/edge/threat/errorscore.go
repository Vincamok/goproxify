// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"strconv"
	"strings"
)

const defaultErrorWeight = 0.5

// builtinErrorWeights : points par défaut d'un 4xx dans le score cumulé. Les requêtes mal formées ou
// non supportées pèsent plus qu'une page introuvable ; 401, 403 et 429 ne comptent pas.
var builtinErrorWeights = map[int]float64{
	400: 1, 404: 0.5, 405: 1, 414: 1, 431: 1,
	401: 0, 403: 0, 429: 0,
}

// points retourne les points d'une réponse 4xx pour ce chemin (0 = ne compte pas).
func (c ErrorScoreConfig) points(status int, path string) float64 {
	w, ok := builtinErrorWeights[status]
	if !ok {
		w = defaultErrorWeight
		if c.DefaultWeight > 0 {
			w = c.DefaultWeight
		}
	}
	if v, ok := c.Weights[strconv.Itoa(status)]; ok && v >= 0 {
		w = v
	}
	if w <= 0 {
		return 0
	}
	return w * c.routeFactor(path)
}

// routeFactor retourne le multiplicateur du préfixe de chemin le plus long qui correspond (1 sinon).
func (c ErrorScoreConfig) routeFactor(path string) float64 {
	best, factor := -1, 1.0
	for _, r := range c.Routes {
		p := strings.TrimSpace(r.Prefix)
		if p == "" || r.Factor < 0 || len(p) <= best || !strings.HasPrefix(path, p) {
			continue
		}
		best, factor = len(p), r.Factor
	}
	return factor
}
