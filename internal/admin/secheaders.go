// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"
)

// adminCSP se limite aux directives qui ne dépendent pas du code de la page : l'interface compte ~1 100 gestionnaires
// d'événements en ligne (onclick=…) et des milliers de style= en ligne, qu'une directive script-src ou style-src sans
// 'unsafe-inline' casserait et qu'avec 'unsafe-inline' elle ne protégerait plus.
const adminCSP = "frame-ancestors 'none'; base-uri 'self'; object-src 'none'"

// securityHeaders pose sur chaque réponse de l'Admin les en-têtes qui ferment les attaques les plus courantes contre une
// interface d'administration : intégration dans le cadre d'un autre site (clickjacking), détournement de <base>, reniflage
// du type des fichiers, fuite de l'adresse de l'Admin dans le Referer, accès aux capteurs du navigateur. HSTS seulement
// si la connexion est en TLS ici : derrière un proxy, c'est à lui de l'annoncer. Les réponses de l'API ne sont pas mises en
// cache. Un gestionnaire qui pose lui-même l'un de ces en-têtes garde la main.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Content-Security-Policy", adminCSP)
		h.Set("Referrer-Policy", "same-origin")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
		if r.TLS != nil {
			h.Set("Strict-Transport-Security", "max-age=31536000")
		}
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}
