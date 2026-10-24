// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

// TLSFingerprintEntry : une empreinte TLS (JA4) et son activité sur la période.
// JA3 est une valeur vue avec ce JA4 (elle varie quand le client randomise ses extensions).
// UniqueIPs ignore les IP tronquées ou pseudonymisées, qui ne désignent pas un client.
// Flagged compte les requêtes que le WAF ou Ephor ont signalées : un JA4 très signalé est la
// signature d'un scanner ou d'un scraper, candidate à `custom_lists.tls_fingerprints`.
type TLSFingerprintEntry struct {
	JA4       string `json:"ja4"`
	JA3       string `json:"ja3,omitempty"`
	Requests  int64  `json:"requests"`
	Errors    int64  `json:"errors"`
	Flagged   int64  `json:"flagged"`
	UniqueIPs int64  `json:"unique_ips"`
}

