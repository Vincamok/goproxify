// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

// handlePortalDestInventory range l'inventaire qu'une passerelle vient de lire chez un fournisseur (ADR 0024). Un inventaire
// illisible ou sans passerelle est ignoré : le passage suivant remplace de toute façon l'état.
func (m *Manager) handlePortalDestInventory(raw json.RawMessage) {
	var p edgeWS.PortalDestInventoryPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" || p.SourceID == "" {
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if err := api.ApplyDestInventory(ctx, m.db, m.log, m.groupResolver(), m, p.NodeName, p.Inventory); err != nil {
		m.log.Warn("portail: inventaire de source non traité", "source", p.SourceID, "node", p.NodeName, "err", err)
	}
}
