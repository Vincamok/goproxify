// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"database/sql"
	"encoding/json"

	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

// Les destinations SIEM portent des jetons dans des en-têtes dont on ne connaît pas le nom (Authorization, X-Api-Key,
// DD-API-KEY…) : la rédaction par fragments de nom n'en attrape qu'une partie. Le réglage logs.siem est donc rédigé
// à part, valeur d'en-tête par valeur d'en-tête ; la section secrets chiffrée garde la configuration entière.

func isSIEMSetting(table string, row map[string]any) bool {
	k, _ := row["key"].(string)
	return table == "settings" && k == siemcfg.SettingKey
}

// redactSIEMSetting vide la valeur de chaque en-tête de chaque destination. Une valeur illisible est vidée entière :
// dans le doute, rien ne sort.
func redactSIEMSetting(value string) string {
	var cfg siem.Config
	if json.Unmarshal([]byte(value), &cfg) != nil {
		return ""
	}
	for i := range cfg.Destinations {
		for k := range cfg.Destinations[i].Headers {
			cfg.Destinations[i].Headers[k] = ""
		}
	}
	out, err := json.Marshal(cfg)
	if err != nil {
		return ""
	}
	return string(out)
}

// mergeSIEMSetting prépare la valeur à restaurer : un en-tête rédigé retrouve la valeur déjà en place pour la même
// destination et le même nom, comme un secret rédigé n'écrase jamais une valeur existante. Sans valeur en place, il reste
// vide : le jeton se ressaisit, ou se restaure par la section secrets.
func mergeSIEMSetting(db *sql.DB, incoming string) string {
	var in siem.Config
	if json.Unmarshal([]byte(incoming), &in) != nil {
		return incoming
	}
	prev := siemcfg.Load(db)
	old := map[string]siem.Destination{}
	for _, d := range prev.Destinations {
		old[d.ID] = d
	}
	for i := range in.Destinations {
		for k, v := range in.Destinations[i].Headers {
			if v == "" {
				if kept, ok := old[in.Destinations[i].ID].Headers[k]; ok {
					in.Destinations[i].Headers[k] = kept
				}
			}
		}
	}
	out, err := json.Marshal(in)
	if err != nil {
		return incoming
	}
	return string(out)
}
