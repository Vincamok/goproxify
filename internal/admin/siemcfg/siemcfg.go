// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package siemcfg garde côté Admin la configuration de l'exporteur SIEM des passerelles (ADR 0012). Elle est poussée à
// chaque passerelle, qui en garde une copie chiffrée et exporte seule, sans l'Admin.
package siemcfg

import (
	"crypto/rand"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"slices"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

// SettingKey est la clé du réglage qui porte la configuration.
const SettingKey = "logs.siem"

// Masked remplace la valeur d'un en-tête secret dans les réponses de l'API : une valeur renvoyée telle quelle à
// l'enregistrement garde le secret déjà stocké.
const Masked = "********"

// Load lit la configuration ; absente ou illisible, l'exporteur est éteint.
func Load(db *sql.DB) siem.Config {
	var cfg siem.Config
	if raw := admindb.GetSetting(db, SettingKey, ""); raw != "" {
		_ = json.Unmarshal([]byte(raw), &cfg)
	}
	return cfg
}

// Save enregistre la configuration.
func Save(db *sql.DB, cfg siem.Config) error {
	raw, err := json.Marshal(cfg)
	if err != nil {
		return err
	}
	return admindb.SetSetting(db, SettingKey, string(raw))
}

func clone(cfg siem.Config) siem.Config {
	out := siem.Config{Enabled: cfg.Enabled, Destinations: make([]siem.Destination, len(cfg.Destinations))}
	for i, d := range cfg.Destinations {
		if d.Headers != nil {
			h := make(map[string]string, len(d.Headers))
			for k, v := range d.Headers {
				h[k] = v
			}
			d.Headers = h
		}
		d.Kinds = append([]string(nil), d.Kinds...)
		out.Destinations[i] = d
	}
	return out
}

// Mask rend la configuration sans les valeurs des en-têtes : ce sont des jetons.
func Mask(cfg siem.Config) siem.Config {
	out := clone(cfg)
	for i := range out.Destinations {
		for k := range out.Destinations[i].Headers {
			out.Destinations[i].Headers[k] = Masked
		}
	}
	return out
}

func newID() string {
	b := make([]byte, 6)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// Merge prépare la configuration reçue de l'API : un en-tête resté masqué retrouve sa valeur enregistrée (même
// destination, même nom), une destination sans identifiant en reçoit un.
func Merge(prev, next siem.Config) siem.Config {
	out := clone(next)
	old := map[string]siem.Destination{}
	for _, d := range prev.Destinations {
		old[d.ID] = d
	}
	for i := range out.Destinations {
		d := &out.Destinations[i]
		if d.ID == "" {
			d.ID = newID()
		}
		for k, v := range d.Headers {
			if v == Masked {
				if kept, ok := old[d.ID].Headers[k]; ok {
					d.Headers[k] = kept
				}
			}
		}
	}
	return out
}

// ForNode rend la configuration qu'une passerelle reçoit : seulement les destinations qui la visent (ou qui visent
// toutes les passerelles), sans le champ nodes. Une destination retirée de la liste d'une passerelle y est éteinte, et
// son curseur avec elle.
func ForNode(cfg siem.Config, node string) siem.Config {
	out := siem.Config{Enabled: cfg.Enabled}
	for _, d := range clone(cfg).Destinations {
		if len(d.Nodes) > 0 && !slices.Contains(d.Nodes, node) {
			continue
		}
		d.Nodes = nil
		out.Destinations = append(out.Destinations, d)
	}
	return out
}

// NodeStatus est l'état de l'exporteur SIEM d'une passerelle, tel qu'elle l'a rapporté.
type NodeStatus struct {
	NodeName     string                   `json:"node_name"`
	ReportedAt   string                   `json:"reported_at"`
	Stale        bool                     `json:"stale,omitempty"`
	Destinations []siem.DestinationStatus `json:"destinations"`
}
