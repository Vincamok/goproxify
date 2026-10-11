// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/security"
)

// Les routes /internal/v1/* sont appelées par les nœuds avec leur jeton d'appairage. Un nœud compromis, ou un bogue,
// ne doit pas pouvoir remplir la base ni banir n'importe quoi : les lots sont bornés, les adresses validées, les
// champs tronqués.
const (
	maxInternalBatch  = 5000
	maxInternalBans   = 1000
	maxInternalString = 2048
)

func clip(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return strings.ToValidUTF8(s[:n], "")
}

// tooLargeBatch répond 413 et indique s'il faut s'arrêter.
func tooLargeBatch(w http.ResponseWriter, n, max int) bool {
	if n <= max {
		return false
	}
	http.Error(w, "lot trop volumineux", http.StatusRequestEntityTooLarge)
	return true
}

// internalBanTarget valide l'adresse d'un ban annoncé par un nœud : une adresse ou une plage lisible, pas plus large
// que ce qu'accepte un ban manuel, et que la liste blanche ne protège pas.
func internalBanTarget(whitelist []security.WhitelistEntry, raw string) (string, bool) {
	t, err := security.ParseBanTarget(raw)
	if err != nil {
		return "", false
	}
	if _, exempt := security.WhitelistCovering(whitelist, t.Prefix); exempt {
		return "", false
	}
	return t.Value, true
}
