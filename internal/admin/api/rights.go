// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// RightsHandler expose le catalogue des droits (ADR 0022) à ceux qui composent des accès d'équipe.
//
//	GET  /api/v1/rights/catalog   services, niveaux, permissions explicites, critères de périmètre et profils
//	POST /api/v1/rights/preview   {"perimeter": {…}} → les proxys que ce périmètre couvre
//
// Routes d'administrateur : le middleware adminOnly est appliqué dans server.go.
type RightsHandler struct {
	Log *slog.Logger
	// Routes rend tous les proxys configurés (aperçu d'un périmètre).
	Routes func(ctx context.Context) ([]router.Route, error)
	// Groups rend un cliché des groupes de passerelles ; nil = les critères de groupe ne couvrent rien.
	Groups func() rbac.GroupCatalog
}

type rightsCatalog struct {
	Services []rbac.Service `json:"services"`
	Profiles []rbac.Profile `json:"profiles"`
	Criteria []string       `json:"criteria"`
}

type previewProxy struct {
	ID   string `json:"id"`
	Name string `json:"name"`
	Host string `json:"host"`
}

// previewLimit borne la liste renvoyée : le total est toujours exact.
const previewLimit = 200

func (h *RightsHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	switch sub := strings.Trim(strings.TrimPrefix(r.URL.Path, "/api/v1/rights"), "/"); {
	case r.Method == http.MethodGet && sub == "catalog":
		jsonOK(w, rightsCatalog{
			Services: rbac.Services,
			Profiles: rbac.Profiles,
			Criteria: []string{string(rbac.CriterionDomain), string(rbac.CriterionProxy), string(rbac.CriterionBackend), string(rbac.CriterionGateway), string(rbac.CriterionLabel)},
		})
	case r.Method == http.MethodPost && sub == "preview":
		h.preview(w, r)
	default:
		writeErr(w, r, http.StatusNotFound, "api.err.not_found")
	}
}

func (h *RightsHandler) preview(w http.ResponseWriter, r *http.Request) {
	var req struct {
		Perimeter rbac.Perimeter `json:"perimeter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeErr(w, r, http.StatusBadRequest, "api.err.json_body")
		return
	}
	if err := req.Perimeter.Validate(); err != nil {
		http.Error(w, err.Error(), http.StatusBadRequest)
		return
	}
	if h.Routes == nil {
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.internal")
		return
	}
	routes, err := h.Routes(r.Context())
	if err != nil {
		h.Log.Warn("rights/preview: lecture des proxys", "err", err)
		writeErr(w, r, http.StatusServiceUnavailable, "api.err.no_edge")
		return
	}
	var groups rbac.GroupCatalog
	if h.Groups != nil {
		groups = h.Groups()
	}
	covered := req.Perimeter.Preview(routes, groups)
	out := struct {
		Count   int            `json:"count"`
		Total   int            `json:"total"`
		Proxies []previewProxy `json:"proxies"`
	}{Count: len(covered), Total: len(routes), Proxies: []previewProxy{}}
	for i := range covered {
		if i == previewLimit {
			break
		}
		out.Proxies = append(out.Proxies, previewProxy{ID: covered[i].ID, Name: rbac.ProxyName(&covered[i]), Host: covered[i].Host})
	}
	jsonOK(w, out)
}
