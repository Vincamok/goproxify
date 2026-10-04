// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"context"
	"database/sql"
	"fmt"
	"net/url"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
)

const gatewayLabel = "gateway"

// InfoPrefix marque un avertissement purement informatif : à journaliser, sans alerte.
const InfoPrefix = "info: "

// bigFileNote : taille à partir de laquelle un fichier de passerelle est signalé dans le journal.
const bigFileNote = 2 << 20

// collectGateways interroge chaque passerelle enregistrée et renvoie ses fichiers d'état sous la
// clé "gateway/<passerelle>/<chemin>". Une passerelle injoignable est signalée, pas bloquante.
func collectGateways(db *sql.DB) (map[string][]byte, []string) {
	out := map[string][]byte{}
	targets, err := edgeproxy.ListTargets(context.Background(), db)
	if err != nil || len(targets) == 0 {
		return out, nil
	}
	var warnings []string
	client := edgeproxy.NewBackupClient()
	for _, t := range targets {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		b, err := client.BackupExport(ctx, t)
		cancel()
		if err != nil {
			warnings = append(warnings, fmt.Sprintf("passerelle %s injoignable, état non sauvegardé : %v", t.NodeName, err))
			continue
		}
		for rel, data := range b.Files {
			out[gatewayLabel+"/"+url.PathEscape(t.NodeName)+"/"+rel] = data
		}
		for _, s := range b.Skipped {
			warnings = append(warnings, fmt.Sprintf("passerelle %s : %s non sauvegardé", t.NodeName, s))
		}
		// Les fichiers qui pèsent le plus, pour comprendre la taille d'un snapshot (journal seulement).
		for rel, size := range b.Sizes {
			if size >= bigFileNote {
				warnings = append(warnings, fmt.Sprintf("%spasserelle %s : %s = %d Mo", InfoPrefix, t.NodeName, rel, size>>20))
			}
		}
	}
	return out, warnings
}

// GatewayRestore : résultat de la restauration de l'état d'une passerelle.
type GatewayRestore struct {
	Gateway         string   `json:"gateway"`
	Written         int      `json:"written"`
	Rejected        []string `json:"rejected,omitempty"`
	Error           string   `json:"error,omitempty"`
	RestartRequired bool     `json:"restart_required"`
}

// restoreGateways renvoie à chaque passerelle de la sauvegarde (identifiée par son nom) son état.
// Une passerelle absente de l'instance courante est signalée en erreur, jamais ignorée en silence.
func restoreGateways(db *sql.DB, files map[string][]byte) []GatewayRestore {
	perNode := map[string]map[string][]byte{}
	for name, data := range files {
		rest := strings.TrimPrefix(name, gatewayLabel+"/")
		node, rel, ok := strings.Cut(rest, "/")
		if !ok {
			continue
		}
		n, err := url.PathUnescape(node)
		if err != nil {
			continue
		}
		if perNode[n] == nil {
			perNode[n] = map[string][]byte{}
		}
		perNode[n][rel] = data
	}
	targets, _ := edgeproxy.ListTargets(context.Background(), db)
	byName := map[string]edgeproxy.Target{}
	for _, t := range targets {
		byName[t.NodeName] = t
	}
	client := edgeproxy.NewBackupClient()
	var out []GatewayRestore
	for node, fs := range perNode {
		r := GatewayRestore{Gateway: node}
		t, ok := byName[node]
		if !ok {
			r.Error = "passerelle non enregistrée sur cette instance : l'enregistrer puis relancer la restauration"
			out = append(out, r)
			continue
		}
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		res, err := client.BackupRestore(ctx, t, &edgeproxy.BackupBundle{Files: fs})
		cancel()
		if err != nil {
			r.Error = err.Error()
		} else {
			r.Written, r.Rejected, r.RestartRequired = res.Written, res.Rejected, res.RestartRequired
		}
		out = append(out, r)
	}
	return out
}
