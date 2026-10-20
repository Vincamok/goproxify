// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package gdpr

import (
	"database/sql"
	"fmt"
	"github.com/vincamok/goproxify/internal/ipcrypt"
)

// QueueEdgeErasure mémorise une IP effacée pour la rejouer aux passerelles qui n'étaient pas
// connectées. L'IP est chiffrée : la base ne la garde pas en clair après l'effacement.
func QueueEdgeErasure(db *sql.DB, key []byte, ip string) error {
	enc, err := ipcrypt.Encrypt(key, ipcrypt.CanonicalIP(ip))
	if err != nil {
		return err
	}
	_, err = db.Exec(`INSERT INTO edge_erasure_queue (ip_enc) VALUES (?)`, enc)
	return err
}

// PendingEdgeErasures retourne les IP en attente, sans doublon. Une ligne illisible (clé changée)
// est ignorée : elle ne peut plus être rejouée et sera purgée avec la rétention.
func PendingEdgeErasures(db *sql.DB, key []byte) ([]string, error) {
	rows, err := db.Query(`SELECT ip_enc FROM edge_erasure_queue ORDER BY id`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	seen := map[string]bool{}
	var out []string
	for rows.Next() {
		var enc string
		if err := rows.Scan(&enc); err != nil {
			return nil, err
		}
		ip, err := ipcrypt.Decrypt(key, enc)
		if err != nil || seen[ip] {
			continue
		}
		seen[ip] = true
		out = append(out, ip)
	}
	return out, rows.Err()
}

// PurgeEdgeErasures supprime les ordres plus vieux que days : les accès de la base de logs des passerelles
// ne gardent pas plus longtemps (365 jours par défaut), il n'y a plus rien à effacer.
func PurgeEdgeErasures(db *sql.DB, days int) error {
	_, err := db.Exec(`DELETE FROM edge_erasure_queue WHERE created_at < datetime('now', ?)`, fmt.Sprintf("-%d days", days))
	return err
}
