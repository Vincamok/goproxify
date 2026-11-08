// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"net/url"
	"strings"
)

// CleanOrigin ne rend que l'origine http(s) bien formée de s (schéma://hôte[:port][/préfixe], sans slash final), sinon "".
// À passer avant d'écrire une adresse dans un href : un schéma comme javascript:, des identifiants, une requête ou un
// fragment n'ont rien à faire dans l'adresse d'un service.
func CleanOrigin(s string) string {
	s = strings.TrimSpace(s)
	u, err := url.Parse(s)
	if err != nil || (u.Scheme != "http" && u.Scheme != "https") || u.Host == "" || u.Hostname() == "" {
		return ""
	}
	if u.User != nil || u.Opaque != "" || u.RawQuery != "" || u.ForceQuery || u.Fragment != "" || strings.Contains(s, "#") {
		return ""
	}
	return u.Scheme + "://" + u.Host + strings.TrimRight(u.EscapedPath(), "/")
}
