// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"net/http"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

// SIEMControl pousse la configuration de l'exporteur SIEM aux passerelles et rend leur état.
type SIEMControl interface {
	PushSIEMConfig(ctx context.Context)
	SIEMStatus() []siemcfg.NodeStatus
}

// siemConfig est la configuration de l'exporteur SIEM. Les en-têtes sont des jetons : la lecture les masque, et une
// valeur renvoyée masquée garde le jeton enregistré.
func (h *LogsHandler) getSIEM(w http.ResponseWriter, r *http.Request) {
	jsonOK(w, siemcfg.Mask(siemcfg.Load(h.DB)))
}

func (h *LogsHandler) putSIEM(w http.ResponseWriter, r *http.Request) {
	var next siem.Config
	if err := json.NewDecoder(http.MaxBytesReader(w, r.Body, 1<<20)).Decode(&next); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json")
		return
	}
	cfg := siemcfg.Merge(siemcfg.Load(h.DB), next)
	if err := cfg.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if err := siemcfg.Save(h.DB, cfg); err != nil {
		logsJSONErr(w, err, http.StatusInternalServerError)
		return
	}
	_ = admindb.WriteAudit(h.DB, adminauth.UserIDFromContext(r.Context()), "logs_siem_config", "logs", siemAuditDetail(cfg))
	if h.SIEM != nil {
		h.SIEM.PushSIEMConfig(context.Background())
	}
	jsonOK(w, siemcfg.Mask(cfg))
}

// siemAuditDetail décrit la configuration pour l'audit, sans aucun secret.
func siemAuditDetail(cfg siem.Config) string {
	detail := "enabled=false"
	if cfg.Enabled {
		detail = "enabled=true"
	}
	for _, d := range cfg.Destinations {
		detail += " " + d.Type + ":" + d.Name
	}
	return detail
}

func (h *LogsHandler) siemStatus(w http.ResponseWriter, r *http.Request) {
	nodes := []siemcfg.NodeStatus{}
	if h.SIEM != nil {
		nodes = append(nodes, h.SIEM.SIEMStatus()...)
	}
	jsonOK(w, map[string]any{"nodes": nodes})
}
