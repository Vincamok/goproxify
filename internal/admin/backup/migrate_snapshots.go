// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"bytes"
	"os"
	"time"
)

// MigrateSnapshotsToFiles libère de la base les snapshots que snapDir contient déjà. Avant le stockage en
// fichier, chaque snapshot (une centaine de Mo avec l'état des passerelles) était gardé deux fois : dans
// la colonne data de backup_snapshots et dans snapDir, soit 1,7 Go de base pour 12 snapshots sur un
// serveur réel. La copie en base n'est vidée qu'une fois le fichier relu et reconnu identique ; sans
// fichier, il est d'abord écrit depuis la base. Idempotent, une ligne à la fois. Retourne le nombre de
// snapshots libérés.
func (s *Scheduler) MigrateSnapshotsToFiles() int {
	if s.snapDir == "" {
		return 0
	}
	rows, err := s.db.Query(`SELECT id, name, created_at FROM backup_snapshots WHERE length(data) > 0`)
	if err != nil {
		return 0
	}
	type row struct{ id, name, created string }
	var todo []row
	for rows.Next() {
		var r row
		if rows.Scan(&r.id, &r.name, &r.created) == nil {
			todo = append(todo, r)
		}
	}
	rows.Close()

	freed := 0
	for _, r := range todo {
		var inDB string
		if err := s.db.QueryRow(`SELECT data FROM backup_snapshots WHERE id=?`, r.id).Scan(&inDB); err != nil || inDB == "" {
			continue
		}
		data := []byte(inDB)
		inDB = ""
		path := s.snapFilePath(r.id)
		if path == "" {
			at, _ := time.Parse("2006-01-02 15:04:05", r.created)
			if at.IsZero() {
				at = time.Now()
			}
			if !s.writeSnapFile(r.id, r.name, data, at) {
				continue
			}
			path = s.snapFilePath(r.id)
		}
		onDisk, err := os.ReadFile(path)
		if err != nil || !bytes.Equal(onDisk, data) {
			s.log.Warn("backup: fichier de snapshot différent de la copie en base, copie conservée", "id", r.id)
			continue
		}
		if _, err := s.db.Exec(`UPDATE backup_snapshots SET data='' WHERE id=?`, r.id); err == nil {
			freed++
		}
	}
	if freed > 0 {
		s.log.Info("backup: snapshots libérés de la base (le fichier de snapDir fait référence)", "snapshots", freed)
	}
	return freed
}
