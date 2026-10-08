// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"io"
	"net/http"
	"strings"
)

const challengePrefix = "_acme-challenge"

// challengeLabel donne le nom de l'enregistrement de challenge pour host, relatif à zone : les
// API d'OVH et de Hetzner attendent un nom relatif à la zone (« _acme-challenge » pour l'apex,
// « _acme-challenge.app » pour app.<zone>), jamais le nom complet, qui produirait
// « _acme-challenge.example.com.example.com ». Sans zone connue, ou pour un hôte hors de la
// zone, le nom complet est retourné.
func challengeLabel(host, zone string) string {
	host = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(host)), ".")
	zone = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(zone)), ".")
	switch {
	case zone == "":
		return challengePrefix + "." + host
	case host == zone:
		return challengePrefix
	case strings.HasSuffix(host, "."+zone):
		return challengePrefix + "." + strings.TrimSuffix(host, "."+zone)
	default:
		return challengePrefix + "." + host
	}
}

// httpClient retourne c, ou le client par défaut (les tests injectent le leur).
func httpClient(c *http.Client) *http.Client {
	if c != nil {
		return c
	}
	return http.DefaultClient
}

// bodyText lit un corps de réponse d'erreur, borné.
func bodyText(r io.Reader) string {
	b, _ := io.ReadAll(io.LimitReader(r, 4<<10))
	return strings.TrimSpace(string(b))
}
