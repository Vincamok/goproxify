// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
)

// Plus de cent cinquante handlers décodent leur corps JSON sans borne : json.Decoder lit tout ce qu'on lui envoie, en
// mémoire. Un client qui envoie plusieurs Gio dans le délai de lecture de 30 s épuise la mémoire de l'Admin — sans
// même être authentifié sur les routes publiques (connexion, appairage, initialisation). Une limite posée à l'entrée,
// avant tout handler, couvre les handlers actuels et futurs ; les handlers qui acceptent plus (import, plugins…)
// gardent leur propre borne, plus basse que celle-ci.
const (
	maxPublicBody = 64 << 10 // routes sans authentification : identifiants, codes, secret d'appairage
	maxAPIBody    = 64 << 20 // le plus gros envoi légitime est l'import de configuration (32 Mio)
)

// publicBodyPaths : routes accessibles sans authentification qui lisent un corps.
var publicBodyPaths = []string{
	"/api/v1/setup/init",
	"/api/v1/auth/",
	"/internal/v1/pair",
}

func bodyLimitFor(path string) int64 {
	for _, p := range publicBodyPaths {
		if path == p || (strings.HasSuffix(p, "/") && strings.HasPrefix(path, p)) {
			return maxPublicBody
		}
	}
	return maxAPIBody
}

// limitRequestBodies borne le corps de chaque requête ; au-delà, la lecture échoue (413 pour les handlers qui
// remontent l'erreur, 400 pour les autres) et la connexion est fermée.
func limitRequestBodies(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Body != nil && r.Body != http.NoBody {
			if r.ContentLength > bodyLimitFor(r.URL.Path) {
				http.Error(w, "corps de requête trop volumineux", http.StatusRequestEntityTooLarge)
				return
			}
			r.Body = http.MaxBytesReader(w, r.Body, bodyLimitFor(r.URL.Path))
		}
		next.ServeHTTP(w, r)
	})
}
