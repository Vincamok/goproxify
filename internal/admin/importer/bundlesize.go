// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"bytes"
	"encoding/json"
	"fmt"
	"sort"
)

// pruneNonSecretTables retire de la section secrets les tables de configuration que la rédaction ne
// modifie pas : elles sont déjà intégralement dans la section standard, les recopier doublait leur
// taille (et la mémoire nécessaire) pour rien. Les tables de secretTables restent entières. Une table
// n'est retirée que si la rédaction, appliquée à une copie, la laisse strictement identique : dans le
// doute elle est conservée.
func pruneNonSecretTables(tables map[string][]map[string]any) {
	keep := map[string]bool{}
	for _, t := range secretTables {
		keep[t] = true
	}
	for _, table := range backupTables {
		if keep[table] {
			continue
		}
		rows := tables[table]
		if len(rows) == 0 {
			continue
		}
		before, err := json.Marshal(rows)
		if err != nil {
			continue
		}
		var clone []map[string]any
		if json.Unmarshal(before, &clone) != nil {
			continue
		}
		redactTables(map[string][]map[string]any{table: clone})
		after, err := json.Marshal(clone)
		if err == nil && bytes.Equal(before, after) {
			delete(tables, table)
		}
	}
}

// bigNote : taille à partir de laquelle une table ou un fichier est signalé dans le journal.
const bigNote = 1 << 20

// SizeNotes liste, pour le journal, les tables et fichiers volumineux d'une sauvegarde (avertissements
// préfixés par InfoPrefix : journalisés sans alerte). Sert à comprendre ce qui pèse dans un snapshot.
func SizeNotes(section string, tables map[string][]map[string]any, files map[string][]byte) []string {
	type item struct {
		name string
		size int
	}
	var items []item
	for table, rows := range tables {
		if b, err := json.Marshal(rows); err == nil && len(b) >= bigNote {
			items = append(items, item{"table " + table, len(b)})
		}
	}
	for name, data := range files {
		if len(data) >= bigNote {
			items = append(items, item{"fichier " + name, len(data)})
		}
	}
	sort.Slice(items, func(i, j int) bool { return items[i].size > items[j].size })
	if len(items) > 8 {
		items = items[:8]
	}
	out := make([]string, 0, len(items))
	for _, it := range items {
		out = append(out, fmt.Sprintf("%scontenu %s : %s = %.1f Mo", InfoPrefix, section, it.name, float64(it.size)/(1<<20)))
	}
	return out
}
