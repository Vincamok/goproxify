// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import "net/http"

// API interne de la passerelle : l'appairage d'un Agent (/internal/v1/pair) n'est protégé que par un secret partagé,
// donc lisible par tout client du réseau, et la plupart des handlers décodent leur JSON sans borne. Une limite
// posée à l'entrée évite qu'un envoi de plusieurs Gio n'épuise la mémoire ; les handlers qui acceptent plus
// (restauration de sauvegarde, 128 Mio) gardent leur propre borne, inférieure à celle-ci.
const (
	maxInternalPublicBody = 64 << 10
	maxInternalBody       = 160 << 20
)

func limitInternalBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			limit := int64(maxInternalBody)
			if r.URL.Path == "/internal/v1/pair" {
				limit = maxInternalPublicBody
			}
			if r.ContentLength > limit {
				http.Error(w, "corps de requête trop volumineux", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, limit)
		}
		next.ServeHTTP(w, r)
	})
}
