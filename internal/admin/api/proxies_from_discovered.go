// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"errors"
	"net/http"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// fromDiscovered convertit une route découverte par les labels en proxy configuré (POST /api/v1/proxies/from-discovered).
// Le proxy est publié sur les passerelles comme n'importe quel proxy ; sur son hôte il prend la place de la route des
// labels, qui reprend l'hôte si le proxy est désactivé ou supprimé.
func (h *ProxiesHandler) fromDiscovered(w http.ResponseWriter, r *http.Request) {
	var body struct {
		ID   string `json:"id"`
		Edge string `json:"edge"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil || body.ID == "" {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}

	c, err := (&DiscoveredContainersHandler{DB: h.DB, Log: h.Log}).ForConversion(r.Context(), body.ID, body.Edge)
	switch {
	case errors.Is(err, ErrContainerNotFound):
		writeErr(w, r, http.StatusNotFound, "api.err.container_not_found")
		return
	case errors.Is(err, ErrContainerEdgeRequired):
		writeErr(w, r, http.StatusConflict, "api.err.container_edge_required")
		return
	case errors.Is(err, ErrContainerAlreadyConverted):
		writeErr(w, r, http.StatusConflict, "api.err.container_already_converted")
		return
	}

	var route router.Route
	if err := json.Unmarshal(c.ProxyConfig, &route); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	route.ID = uuid.New().String()
	route.UpdatedAt = time.Now()
	userID := auth.UserIDFromContext(r.Context())
	if !rbac.CanWriteProxy(r.Context(), h.DB, userID, &route) {
		writeErr(w, r, http.StatusForbidden, "api.err.out_of_scope_domain")
		return
	}
	cfgJSON, err := c.ConversionConfig(route.ID, route.UpdatedAt)
	if err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	prod, err := h.publishAll(r.Context(), route.ID, route.Host, true, cfgJSON, userID)
	if err != nil {
		h.writeEdgeErr(w, r, err)
		return
	}
	_ = admindb.WriteAudit(h.DB, userID, "create", "proxy:"+route.ID, route.Host)

	created := envelopeToRow(prod)
	created.Config = h.maskConfig(created.Config)
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(http.StatusCreated)
	_ = json.NewEncoder(w).Encode(created)
}
