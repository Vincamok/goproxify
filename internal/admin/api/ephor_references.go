// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

// EphorReferences retourne, par passerelle, ce qu'elle a appris pour la note commune d'Ephor : références de débit par route
// et par heure, base ASN, profils en cours. edge (nom du nœud ou identifiant du jeton) restreint à une passerelle.
func EphorReferences(ctx context.Context, db *sql.DB, edge *prismedge.Source, edgeParam string) (map[string]any, error) {
	if edge == nil {
		return nil, errNoGatewayToReplay
	}
	node := edgeParam
	if node != "" {
		var name string
		if db.QueryRowContext(ctx, `SELECT node_name FROM tokens WHERE id=? OR node_name=? LIMIT 1`, node, node).Scan(&name) == nil && name != "" {
			node = name
		}
	}
	gws, meta, err := edge.EphorReferences(ctx, node)
	if err != nil {
		return nil, err
	}
	out := map[string]any{"gateways": gws}
	if meta.Degraded() {
		out["partial"], out["unreachable"] = meta.Partial, meta.Unreachable
	}
	return out, nil
}

func (h *SecurityHandler) getThreatReferences(w http.ResponseWriter, r *http.Request) {
	out, err := EphorReferences(r.Context(), h.DB, h.Edge, r.URL.Query().Get("edge"))
	if err != nil {
		secJSONErr(w, err, http.StatusBadGateway)
		return
	}
	jsonOK(w, out)
}
