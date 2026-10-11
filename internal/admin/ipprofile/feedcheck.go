// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ipprofile

import (
	"net/http"
	"time"
	"fmt"
	"net"
	"net/url"
	"strings"

	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/ssrf"
)

// Une source de profil IP est une URL saisie par un utilisateur et lue par l'Admin : sans garde-fou, elle permettait
// de sonder le réseau interne ou les métadonnées du cloud depuis l'Admin (les erreurs « HTTP 404 », « connexion
// refusée » renseignent sur ce qui répond). GPX_IPPROFILE_ALLOW_PRIVATE=1 autorise les sources internes (miroir de
// listes sur le LAN, Admin derrière un proxy d'entreprise).

// MaxFeedURLs borne le nombre de sources d'un profil.
const MaxFeedURLs = 10

// MaxRefreshIntervalH borne l'intervalle de rafraîchissement (un an).
const MaxRefreshIntervalH = 8760

var knownFormats = map[string]bool{"plain": true, "json-aws": true, "json-gcp": true, "json-fastly": true, "tsv-dshield": true}

// AllowPrivateFeeds indique si les sources sur réseau interne sont autorisées.
func AllowPrivateFeeds() bool { return ssrf.AllowPrivateEnv("GPX_IPPROFILE_ALLOW_PRIVATE") }

// ValidateFeed contrôle les sources et le format d'un profil. Un format inconnu était lu comme du texte brut, sans
// erreur : un profil « json-aws » mal orthographié n'avait aucune plage.
func ValidateFeed(urls []string, format string, allowPrivate bool) error {
	if len(urls) > MaxFeedURLs {
		return fmt.Errorf("%d sources au plus", MaxFeedURLs)
	}
	if format != "" && !knownFormats[format] {
		return fmt.Errorf("feed_format inconnu %q (plain, json-aws, json-gcp, json-fastly, tsv-dshield)", format)
	}
	for _, raw := range urls {
		u, err := url.Parse(strings.TrimSpace(raw))
		if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Hostname() == "" {
			return fmt.Errorf("source %q : URL http(s) requise", raw)
		}
		host := strings.ToLower(u.Hostname())
		if !allowPrivate && (host == "localhost" || strings.HasSuffix(host, ".localhost") || host == "metadata.google.internal" ||
			(net.ParseIP(host) != nil && plugins.BlockedHost(host))) {
			return fmt.Errorf("source %q : adresse interne refusée (GPX_IPPROFILE_ALLOW_PRIVATE=1 pour l'autoriser)", raw)
		}
	}
	return nil
}

// feedClient : client HTTP des sources. La connexion elle-même est contrôlée (adresse *résolue*, redirections
// comprises), ce qui déjoue le rebinding DNS qu'un contrôle de l'URL seule laisserait passer.
func feedClient(timeout time.Duration) *http.Client {
	return plugins.SafeHTTPClientFollow(timeout, AllowPrivateFeeds())
}
