// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"database/sql"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// backupTables liste, dans l'ordre de restauration, les tables de configuration
// sauvegardées telle quelles (SELECT *). Les tables d'état (logs, bans, audit,
// MFA, sessions, snapshots, historiques) et les clés de chiffrement (gdpr_keys)
// n'en font volontairement pas partie.
var backupTables = []string{
	"settings",
	"backup_schedule",
	"backup_destinations",
	"fleet_config",
	"crowdsec_config",
	"flows",
	"flow_state",
	"domains",
	"cert_deploy_targets",
	"auth_providers",
	"plugins",
	"plugin_trusted_keys",
	"plugin_repos",
	"ip_profiles",
	"node_tunnel_configs",
	"teams",
	"team_members",
	"team_accesses",
	"error_page_templates",
	"error_page_assets",
	"portal_destinations",
	"portal_users",
	"portal_groups",
	"portal_dest_groups",
	"portal_dest_sources",
	"portal_dest_candidates",
	"portal_logins",
	"automation_silences",
	"flow_versions",
	"portal_page_templates",
}

// blobColumns : colonnes BLOB, encodées en base64 dans le JSON de sauvegarde.
var blobColumns = map[string]bool{"error_page_assets.content": true, "plugins.wasm": true}

// clearedColumns : colonnes dont la valeur ne doit jamais sortir de la base.
//
// Portail Access : `portal_dest_sources.config_enc` porte les identifiants d'API des fournisseurs (scellés par la clé de nœud de
// l'Admin), `portal_logins.secret_sealed` l'enveloppe chiffrée d'un login préconfiguré (illisible de l'Admin, mais jamais en
// clair dans la section standard non plus). Les deux voyagent dans la section secrets, chiffrée par la clé de sauvegarde.
var clearedColumns = map[string]bool{
	"portal_users.invite_token_hash": true,
	"portal_dest_sources.config_enc": true,
	"portal_logins.secret_sealed":    true,
}

// nodeSealedColumns : colonnes scellées par la clé de nœud de l'Admin (auth.SealNodeToken), dérivée du secret JWT ou de
// GPX_NODE_TOKEN_KEY. Ce secret n'est pas restauré : à la reconstruction d'un Admin, le JWT est régénéré et une valeur scellée
// avec l'ancienne clé deviendrait illisible, sans erreur visible (la source se lirait « sans configuration »). La section
// secrets les porte donc en clair (elle est chiffrée par la clé de sauvegarde) et la restauration les scelle avec la clé de
// l'Admin qui restaure.
var nodeSealedColumns = map[string]bool{"portal_dest_sources.config_enc": true}

// unsealNodeColumns remplace, dans les lignes d'une section secrets, les valeurs scellées par la clé de nœud par leur contenu.
// Une valeur illisible (clé de nœud déjà changée) est gardée telle quelle.
func unsealNodeColumns(tables map[string][]map[string]any) {
	for table, rows := range tables {
		for _, row := range rows {
			for col, v := range row {
				if s, ok := v.(string); ok && s != "" && nodeSealedColumns[table+"."+col] {
					if plain, err := auth.OpenNodeToken(s); err == nil && plain != "" {
						row[col] = plain
					}
				}
			}
		}
	}
}

// sealNodeColumns scelle avec la clé de nœud courante les valeurs que unsealNodeColumns a rendues en clair. Une valeur déjà
// scellée (ancienne sauvegarde) est laissée telle quelle par SealNodeToken.
func sealNodeColumns(tables map[string][]map[string]any) {
	for table, rows := range tables {
		for _, row := range rows {
			for col, v := range row {
				if s, ok := v.(string); ok && s != "" && nodeSealedColumns[table+"."+col] {
					row[col] = auth.SealNodeToken(s)
				}
			}
		}
	}
}

var secretFragments = []string{"secret", "password", "passwd", "token", "api_key", "apikey", "private_key", "credential", "webhook_url", "authorization", "routing_key"}

func isSecretKey(k string) bool {
	k = strings.ToLower(k)
	for _, f := range secretFragments {
		if strings.Contains(k, f) {
			return true
		}
	}
	return false
}

func redactJSONValue(v any) any {
	switch x := v.(type) {
	case map[string]any:
		for k, val := range x {
			if _, isStr := val.(string); isStr && isSecretKey(k) {
				x[k] = ""
				continue
			}
			x[k] = redactJSONValue(val)
		}
		return x
	case []any:
		for i := range x {
			x[i] = redactJSONValue(x[i])
		}
		return x
	}
	return v
}

// redactTableValue rédige les secrets d'une valeur texte (JSON ou brute) d'une colonne.
func redactTableValue(table, col string, val any) any {
	if clearedColumns[table+"."+col] {
		return ""
	}
	s, ok := val.(string)
	if !ok || s == "" {
		return val
	}
	var parsed any
	if (strings.HasPrefix(s, "{") || strings.HasPrefix(s, "[")) && json.Unmarshal([]byte(s), &parsed) == nil {
		out, _ := json.Marshal(redactJSONValue(parsed))
		return string(out)
	}
	return val
}

func exportTables(db *sql.DB) map[string][]map[string]any {
	return exportRawTables(db, backupTables)
}

// exportRawTables lit les lignes de tables sans rien rédiger : réservé à la section secrets chiffrée.
func exportRawTables(db *sql.DB, tables []string) map[string][]map[string]any {
	out := map[string][]map[string]any{}
	for _, table := range tables {
		rows, err := db.Query(`SELECT * FROM ` + table)
		if err != nil {
			continue // table absente sur une base ancienne
		}
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
					// encoding/json écrirait du RFC3339, que SQLite compare mal à CURRENT_TIMESTAMP.
					v = sqltime.Format(t)
				}
				if b, ok := v.([]byte); ok {
					if blobColumns[table+"."+c] {
						v = base64.StdEncoding.EncodeToString(b)
					} else {
						v = string(b)
					}
				}
				row[c] = v
			}
			list = append(list, row)
		}
		rows.Close()
		if len(list) > 0 {
			out[table] = list
		}
	}
	return out
}

// redactTables retire les secrets des lignes exportées (clés d'API DNS, secrets OIDC, etc.).
func redactTables(tables map[string][]map[string]any) {
	for table, rows := range tables {
		for _, row := range rows {
			if k, ok := row["key"].(string); ok && isSecretKey(k) {
				row["value"] = ""
				continue
			}
			if isSIEMSetting(table, row) {
				if v, ok := row["value"].(string); ok {
					row["value"] = redactSIEMSetting(v)
				}
				continue
			}
			for col, v := range row {
				row[col] = redactTableValue(table, col, v)
			}
		}
	}
}

// TableRowCount retourne le nombre total de lignes de configuration d'une sauvegarde.
func TableRowCount(tables map[string][]map[string]any) int {
	n := 0
	for _, rows := range tables {
		n += len(rows)
	}
	return n
}

// TableCounts retourne le nombre de lignes par table de configuration.
func TableCounts(tables map[string][]map[string]any) map[string]int {
	out := make(map[string]int, len(tables))
	for t, rows := range tables {
		out[t] = len(rows)
	}
	return out
}

func teamHasPermission(db *sql.DB, teamID any) bool {
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM team_permissions WHERE team_id = ?`, teamID).Scan(&n) //nolint:errcheck
	return n > 0
}

// applyTables restaure les tables de configuration ; retourne le nombre de lignes écrites.
func applyTables(db *sql.DB, tables map[string][]map[string]any, overwrite, allowPrivileged bool) (written, skipped int) {
	return applyTablesOrdered(db, tables, backupTables, overwrite, allowPrivileged)
}

func applyTablesOrdered(db *sql.DB, tables map[string][]map[string]any, order []string, overwrite, allowPrivileged bool) (written, skipped int) {
	verb := `INSERT OR IGNORE`
	if overwrite {
		verb = `INSERT OR REPLACE`
	}
	for _, table := range order {
		rows := tables[table]
		if len(rows) == 0 {
			continue
		}
		valid := tableColumns(db, table)
		if len(valid) == 0 {
			skipped += len(rows)
			continue
		}
		for _, row := range rows {
			// Membres d'une équipe portant une permission (gdpr:reveal) : composition réservée
			// au superadmin, une restauration ne doit pas y ajouter quelqu'un.
			if table == "team_members" && !allowPrivileged && teamHasPermission(db, row["team_id"]) {
				skipped++
				continue
			}
			var cols []string
			var args []any
			var ph []string
			for c, v := range row {
				typ, ok := valid[c]
				if !ok {
					continue
				}
				// Sauvegardes antérieures : dates exportées en RFC3339.
				if s, ok := v.(string); ok && isDateType(typ) {
					v = sqltime.Text(s)
				}
				if s, ok := v.(string); ok && blobColumns[table+"."+c] {
					if b, err := base64.StdEncoding.DecodeString(s); err == nil {
						v = b
					}
				}
				// Une colonne vidée à l'export (secret) n'efface pas la valeur en place : sans cela, restaurer la section
				// standard seule sur une instance qui a ses secrets les écraserait par du vide.
				if s, ok := v.(string); ok && s == "" && clearedColumns[table+"."+c] {
					if id, hasID := row["id"]; hasID {
						var cur string
						if db.QueryRow(`SELECT `+c+` FROM `+table+` WHERE id=?`, id).Scan(&cur) == nil {
							v = cur
						}
					}
				}
				cols = append(cols, c)
				args = append(args, v)
				ph = append(ph, "?")
			}
			if k, ok := row["key"].(string); ok && isSecretKey(k) && row["value"] == "" {
				continue // secret rédigé : ne pas écraser la valeur en place
			}
			if isSIEMSetting(table, row) {
				for i, c := range cols {
					if v, ok := args[i].(string); ok && c == "value" {
						args[i] = mergeSIEMSetting(db, v)
					}
				}
			}
			if len(cols) == 0 {
				continue
			}
			q := fmt.Sprintf(`%s INTO %s (%s) VALUES (%s)`, verb, table, strings.Join(cols, ","), strings.Join(ph, ","))
			if res, err := db.Exec(q, args...); err != nil {
				skipped++
			} else if n, _ := res.RowsAffected(); n > 0 {
				written++
			} else {
				skipped++
			}
		}
	}
	return written, skipped
}

func isDateType(typ string) bool {
	typ = strings.ToUpper(typ)
	return strings.Contains(typ, "DATE") || strings.Contains(typ, "TIME")
}

// tableColumns retourne les colonnes de table et leur type déclaré.
func tableColumns(db *sql.DB, table string) map[string]string {
	rows, err := db.Query(`PRAGMA table_info(` + table + `)`)
	if err != nil {
		return nil
	}
	defer rows.Close()
	cols := map[string]string{}
	for rows.Next() {
		var cid, notnull, pk int
		var name, typ string
		var dflt sql.NullString
		if rows.Scan(&cid, &name, &typ, &notnull, &dflt, &pk) == nil {
			cols[name] = typ
		}
	}
	return cols
}
