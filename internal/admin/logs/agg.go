// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logs

import "time"

// DefaultRetentionAggDays : les cumuls par minute que les passerelles calculent (ADR 0012) ne contiennent aucune donnée
// personnelle (ni IP, ni chemin) ; ils survivent donc aux lignes.
const DefaultRetentionAggDays = 400

// MinuteLayout est le format des minutes de logs_minute : AAAA-MM-JJTHH:MM en UTC.
const MinuteLayout = "2006-01-02T15:04"

// MinuteKey retourne la minute de t, au format de logs_minute.
func MinuteKey(t time.Time) string { return t.UTC().Format(MinuteLayout) }

// purgeAggregates supprime les cumuls plus vieux que la durée de conservation.
func (s *Store) purgeAggregates(days int) {
	cut := time.Now().UTC().AddDate(0, 0, -days).Format(MinuteLayout)
	s.db.Exec(`DELETE FROM logs_minute WHERE minute < ?`, cut) //nolint:errcheck
}
