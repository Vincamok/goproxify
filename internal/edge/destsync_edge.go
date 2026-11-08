// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"

	"github.com/vincamok/goproxify/internal/edge/destsync"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// applyDestSources met les sources de destinations du portail (ADR 0024) en phase avec la config poussée. Seul le membre
// qui héberge le portail interroge les fournisseurs : un réplica en attente garde la config sans l'exécuter, et reprend
// les sources s'il devient actif. La config arrive par la même poussée que le reste du portail : elle est donc déjà dans
// la copie locale chiffrée, et les sources redémarrent sans l'Admin.
func (s *Server) applyDestSources(p portalPushPayload) {
	if s.destSync == nil || p.DestSources == nil {
		return
	}
	s.destSync.Apply(p.DestSources, p.Enabled && !p.HAStandby)
}

// reportDestInventory remet l'inventaire d'une source à l'Admin.
func (s *Server) reportDestInventory(inv destsync.Inventory) {
	p := edgews.PortalDestInventoryPayload{Inventory: inv}
	if s.cfg != nil {
		p.NodeName = s.cfg.Identity.NodeName
	}
	if msg, err := edgews.NewMessage(0, edgews.TypePortalDestInventory, p); err == nil && s.wsHub != nil {
		s.wsHub.BroadcastToAdmins(msg)
	}
}

type destSourceTestRequest struct {
	Type   string         `json:"type"`
	Config map[string]any `json:"config"`
}

type destSourceTestResponse struct {
	OK       bool               `json:"ok"`
	Error    string             `json:"error,omitempty"`
	Count    int                `json:"count"`
	Machines []destsync.Machine `json:"machines,omitempty"` // les premières seulement : c'est un aperçu
}

const destTestPreview = 20

// handleDestSourceTest lit une fois une source avec la configuration reçue, sans rien retenir : le fournisseur doit être
// joignable depuis la passerelle, c'est donc d'ici que le bouton « Tester » de l'Admin interroge.
func (s *Server) handleDestSourceTest(w http.ResponseWriter, r *http.Request) {
	var req destSourceTestRequest
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&req); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	machines, err := destsync.Test(r.Context(), req.Type, req.Config)
	if err != nil {
		writeJSON(w, destSourceTestResponse{Error: err.Error()})
		return
	}
	out := destSourceTestResponse{OK: true, Count: len(machines), Machines: machines}
	if len(out.Machines) > destTestPreview {
		out.Machines = out.Machines[:destTestPreview]
	}
	writeJSON(w, out)
}

// handleDestSourceSync demande un passage immédiat. 404 : la source ne tourne pas sur cette passerelle (portail
// désactivé, réplica en attente, source désactivée).
func (s *Server) handleDestSourceSync(w http.ResponseWriter, r *http.Request) {
	if s.destSync == nil || !s.destSync.SyncNow(r.PathValue("id")) {
		http.Error(w, "source inactive sur cette passerelle", http.StatusNotFound)
		return
	}
	w.WriteHeader(http.StatusAccepted)
}
