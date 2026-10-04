// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"

	"github.com/vincamok/goproxify/internal/admin/logs"
)

// TLSFingerprintEntry : une empreinte TLS (JA4) et son activité sur la période.
// JA3 est une valeur vue avec ce JA4 (elle varie quand le client randomise ses extensions).
// UniqueIPs ignore les IP tronquées ou pseudonymisées, qui ne désignent pas un client.
// Flagged compte les requêtes que le WAF ou Sentinel ont signalées : un JA4 très signalé est la
// signature d'un scanner ou d'un scraper, candidate à `custom_lists.tls_fingerprints`.
type TLSFingerprintEntry struct {
	JA4       string `json:"ja4"`
	JA3       string `json:"ja3,omitempty"`
	Requests  int64  `json:"requests"`
	Errors    int64  `json:"errors"`
	Flagged   int64  `json:"flagged"`
	UniqueIPs int64  `json:"unique_ips"`
}

// GetTopTLSFingerprints retourne les empreintes JA4 les plus actives. Les requêtes sans empreinte
// (HTTP clair, HTTP/3, entrées antérieures à leur stockage) sont ignorées.
func GetTopTLSFingerprints(db *sql.DB, p Params, limit int) []TLSFingerprintEntry {
	if limit <= 0 {
		limit = 30
	}
	w, wargs := where(p)
	args := append([]any{logs.PseudonymizedIP}, wargs...)
	args = append(args, limit)
	ctx, cancel := context.WithTimeout(context.Background(), queryTimeout)
	defer cancel()
	rows, err := db.QueryContext(ctx,
		`SELECT tls_ja4, COALESCE(MAX(tls_ja3),''), COUNT(*) AS n,
		        SUM(CASE WHEN status>=400 THEN 1 ELSE 0 END),
		        SUM(CASE WHEN threat_signal <> '' OR waf_matches <> '' THEN 1 ELSE 0 END),
		        COUNT(DISTINCT CASE WHEN ip_truncated = 0 AND ip <> ? THEN ip END)
		 FROM logs `+w+` AND tls_ja4 <> '' GROUP BY tls_ja4 ORDER BY n DESC LIMIT ?`,
		args...)
	if err != nil {
		return []TLSFingerprintEntry{}
	}
	defer rows.Close()
	out := []TLSFingerprintEntry{}
	for rows.Next() {
		var e TLSFingerprintEntry
		rows.Scan(&e.JA4, &e.JA3, &e.Requests, &e.Errors, &e.Flagged, &e.UniqueIPs) //nolint:errcheck
		out = append(out, e)
	}
	return out
}
