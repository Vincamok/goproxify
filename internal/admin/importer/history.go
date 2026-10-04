// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/vincamok/goproxify/internal/sqltime"
)

const historyEncPrefix = "GPXHIS1:"

// historyTables : données d'état passées, volumineuses et sensibles (adresses IP, actions
// d'administrateurs). Elles ne sont sauvegardées qu'à la demande et toujours chiffrées.
var historyTables = []string{
	"audit_log",
	"logs",
	"node_events",
	"alert_events",
	"security_bans",
	"security_ban_history",
	"security_cves",
	"security_threats",
	"vulnscan_state",
	"cert_deploy_history",
	"rules_engine_history",
	"rules_engine_pending_actions",
	"playbook_runs",
	"scheduled_task_runs",
	"portal_audit",
	"portal_access_requests",
	"proxy_history",
}

// historyRowCap borne le nombre de lignes (les plus récentes) exportées par table.
var historyRowCap = map[string]int{"logs": 100000}

const defaultHistoryRowCap = 500000

// HistoryBundle : lignes brutes des tables d'historique.
type HistoryBundle struct {
	Tables    map[string][]map[string]any `json:"tables"`
	Truncated map[string]int              `json:"truncated,omitempty"` // table → lignes non exportées
	CreatedAt time.Time                   `json:"created_at"`
}

// AttachHistory joint l'historique chiffré à b. Sans GPX_BACKUP_KEY : ErrNoBackupKey, rien n'est écrit.
func AttachHistory(db *sql.DB, b *Backup) error {
	if _, ok := BackupKey(); !ok {
		return ErrNoBackupKey
	}
	hb := HistoryBundle{Tables: map[string][]map[string]any{}, Truncated: map[string]int{}, CreatedAt: time.Now()}
	for _, table := range historyTables {
		limit := defaultHistoryRowCap
		if c, ok := historyRowCap[table]; ok {
			limit = c
		}
		rows := exportRawTableLimited(db, table, limit)
		if len(rows) > 0 {
			hb.Tables[table] = rows
		}
		var total int
		if db.QueryRow(`SELECT COUNT(*) FROM `+table).Scan(&total) == nil && total > len(rows) {
			hb.Truncated[table] = total - len(rows)
		}
	}
	plain, err := json.Marshal(hb)
	if err != nil {
		return err
	}
	b.History, err = sealWith(historyEncPrefix, plain)
	return err
}

func openHistory(b *Backup) (*HistoryBundle, error) {
	if b.History == "" {
		return nil, errors.New("cette sauvegarde ne contient pas d'historique")
	}
	plain, err := openWith(historyEncPrefix, b.History)
	if err != nil {
		return nil, fmt.Errorf("historique : %w", err)
	}
	var hb HistoryBundle
	if err := json.Unmarshal(plain, &hb); err != nil {
		return nil, err
	}
	return &hb, nil
}

// HistorySummary : contenu de la section historique, sans rien écrire.
type HistorySummary struct {
	Tables    map[string]int `json:"tables"`
	Truncated map[string]int `json:"truncated,omitempty"`
}

// OpenHistorySummary déchiffre l'historique et en résume le contenu.
func OpenHistorySummary(b *Backup) (*HistorySummary, error) {
	hb, err := openHistory(b)
	if err != nil {
		return nil, err
	}
	return &HistorySummary{Tables: TableCounts(hb.Tables), Truncated: hb.Truncated}, nil
}

// restoreHistory ajoute les lignes d'historique : une ligne dont l'identifiant existe déjà est ignorée.
func restoreHistory(db *sql.DB, b *Backup) (int, error) {
	hb, err := openHistory(b)
	if err != nil {
		return 0, err
	}
	written, _ := applyTablesOrdered(db, hb.Tables, historyTables, false, true)
	return written, nil
}

// exportRawTableLimited lit les `limit` dernières lignes (par rowid) d'une table, sans rédaction.
func exportRawTableLimited(db *sql.DB, table string, limit int) []map[string]any {
	rows, err := db.Query(fmt.Sprintf(`SELECT * FROM %s ORDER BY rowid DESC LIMIT %d`, table, limit))
	if err != nil {
		return nil // table absente sur une base ancienne
	}
	defer rows.Close()
	cols, _ := rows.Columns()
	var list []map[string]any
	for rows.Next() {
		vals := make([]any, len(cols))
		ptrs := make([]any, len(cols))
		for i := range vals {
			ptrs[i] = &vals[i]
		}
		if rows.Scan(ptrs...) != nil {
			continue
		}
		row := make(map[string]any, len(cols))
		for i, c := range cols {
			v := vals[i]
			if t, ok := v.(time.Time); ok {
				v = sqltime.Format(t)
			}
			if bs, ok := v.([]byte); ok {
				v = string(bs)
			}
			row[c] = v
		}
		list = append(list, row)
	}
	return list
}
