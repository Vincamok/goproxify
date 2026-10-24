// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"context"
	"database/sql"
	"fmt"
	"time"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// fetchGroupCards demande leur fiche de groupe aux passerelles appairées (celles de la liste, ou toutes si elle est
// vide). Une passerelle qui n'en détient pas encore n'est pas une erreur ; une qui ne répond pas est rendue avec la
// raison, pour que l'opérateur sache que la reconstitution est partielle.
func fetchGroupCards(ctx context.Context, db *sql.DB, edges []string) (cards []edgeWS.GroupCard, unreachable []string) {
	targets, err := edgeproxy.ListTargets(ctx, db)
	if err != nil {
		return nil, []string{fmt.Sprintf("passerelles : %v", err)}
	}
	want := map[string]bool{}
	for _, e := range edges {
		want[e] = true
	}
	client := edgeproxy.NewClientTimeout(10 * time.Second)
	for _, t := range targets {
		if len(want) > 0 && !want[t.NodeName] && !want[t.ID] {
			continue
		}
		card, found, err := client.GroupCard(ctx, t)
		if err != nil {
			unreachable = append(unreachable, fmt.Sprintf("%s : %v", t.NodeName, err))
			continue
		}
		if found {
			cards = append(cards, card)
		}
	}
	return cards, unreachable
}
