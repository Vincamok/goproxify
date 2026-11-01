// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/proxystore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// Les outils de proxys appliquent à l'utilisateur du PAT les mêmes grants que l'API REST (rbac.Can*Proxy) : le scope du
// jeton dit quels outils sont permis, les grants de l'utilisateur et de ses équipes disent sur quels domaines.

var errProxyOutOfScope = errors.New("proxy hors de votre périmètre")

func (h *Handler) grantsOf(ctx context.Context) (string, []rbac.Grant) {
	userID := adminauth.UserIDFromContext(ctx)
	grants, _ := rbac.UserEffectiveGrants(ctx, h.DB, userID)
	return rbac.UserRole(ctx, h.DB, userID), grants
}

// routeOfConfig est la route que les grants jugent : l'hôte de l'enveloppe sert quand la config n'en porte pas.
func routeOfConfig(id, host string, cfg []byte) *router.Route {
	var route router.Route
	_ = json.Unmarshal(cfg, &route)
	route.ID = id
	if route.Host == "" {
		route.Host = host
	}
	return &route
}

// readableEnvelope donne le filtre des proxys que l'utilisateur peut voir ; ses grants ne sont lus qu'une fois.
func (h *Handler) readableEnvelope(ctx context.Context) func(*proxystore.Envelope) bool {
	role, grants := h.grantsOf(ctx)
	return func(e *proxystore.Envelope) bool {
		return rbac.CanReadProxyWithGrants(role, grants, routeOfConfig(e.ID, e.Host, e.Config))
	}
}

// requireWrite refuse la modification d'un proxy hors du périmètre en écriture de l'utilisateur. Chaque config donnée
// est jugée : celle du proxy avant l'outil, et celle qu'il produirait.
func (h *Handler) requireWrite(ctx context.Context, id, host string, configs ...[]byte) error {
	role, grants := h.grantsOf(ctx)
	for _, cfg := range configs {
		if !rbac.CanWriteProxyWithGrants(role, grants, routeOfConfig(id, host, cfg)) {
			return errProxyOutOfScope
		}
	}
	return nil
}

// requireDelete refuse la suppression d'un proxy hors du périmètre de l'utilisateur.
func (h *Handler) requireDelete(ctx context.Context, env *proxystore.Envelope) error {
	role, grants := h.grantsOf(ctx)
	if !rbac.CanDeleteProxyWithGrants(role, grants, routeOfConfig(env.ID, env.Host, env.Config)) {
		return errProxyOutOfScope
	}
	return nil
}
