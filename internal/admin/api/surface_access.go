// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

// La surface applicative d'un proxy suit les mêmes grants que le proxy : l'API REST et le MCP appellent les mêmes fonctions,
// qui jugent l'utilisateur du contexte avant de lire ou de réécrire quoi que ce soit.

var (
	// ErrSurfaceNotFound : le proxy n'existe pas, ou l'utilisateur n'a pas le droit de le voir.
	ErrSurfaceNotFound = errors.New("proxy introuvable")
	// ErrSurfaceOutOfScope : l'utilisateur voit le proxy mais n'a pas le droit de l'écrire.
	ErrSurfaceOutOfScope = errors.New("proxy hors de votre périmètre")
)

// surfaceStatus traduit un refus d'accès en code HTTP ; toute autre erreur est celle d'une passerelle.
func surfaceStatus(err error) int {
	switch {
	case errors.Is(err, ErrSurfaceNotFound):
		return http.StatusNotFound
	case errors.Is(err, ErrSurfaceOutOfScope):
		return http.StatusForbidden
	}
	return http.StatusBadGateway
}

// routeIndex retrouve la route d'un proxy par son identifiant ou son hôte, dans l'Admin et sur les passerelles.
type routeIndex map[string]*router.Route

func loadRouteIndex(ctx context.Context, db *sql.DB) routeIndex {
	idx := routeIndex{}
	add := func(id, host string, cfg []byte) {
		var route router.Route
		_ = json.Unmarshal(cfg, &route)
		route.ID = id
		if route.Host == "" {
			route.Host = host
		}
		if _, taken := idx[id]; !taken {
			idx[id] = &route
		}
		if h := strings.ToLower(route.Host); h != "" {
			if _, taken := idx[h]; !taken {
				idx[h] = &route
			}
		}
	}
	if rows, err := db.QueryContext(ctx, `SELECT id, name, config FROM proxies`); err == nil {
		for rows.Next() {
			var id, name, cfg string
			if rows.Scan(&id, &name, &cfg) == nil {
				add(id, name, []byte(cfg))
			}
		}
		rows.Close()
	}
	if envs, err := edgeproxy.LoadProductionEnvelopes(ctx, db); err == nil {
		for _, e := range envs {
			add(e.ID, e.Host, e.Config)
		}
	}
	return idx
}

// of rend la route d'une référence (identifiant ou hôte). Une référence inconnue est jugée comme un hôte : seul un compte
// sans périmètre la verra.
func (idx routeIndex) of(ref string) *router.Route {
	if route, ok := idx[ref]; ok {
		return route
	}
	if route, ok := idx[strings.ToLower(ref)]; ok {
		return route
	}
	return &router.Route{Host: ref}
}

// surfaceAccess juge les proxys pour l'utilisateur de la requête ; ses grants et l'index des routes ne sont lus qu'une fois.
type surfaceAccess struct {
	role   string
	grants []rbac.Grant
	routes routeIndex
}

func newSurfaceAccess(ctx context.Context, db *sql.DB) surfaceAccess {
	userID := auth.UserIDFromContext(ctx)
	grants, _ := rbac.UserEffectiveGrants(ctx, db, userID)
	return surfaceAccess{role: rbac.UserRole(ctx, db, userID), grants: grants, routes: loadRouteIndex(ctx, db)}
}

// check refuse l'accès au proxy ref : introuvable s'il est hors du périmètre en lecture, interdit s'il l'est en écriture.
func (a surfaceAccess) check(ref string, write bool) error {
	route := a.routes.of(ref)
	if !rbac.CanReadProxyWithGrants(a.role, a.grants, route) {
		return ErrSurfaceNotFound
	}
	if write && !rbac.CanWriteProxyWithGrants(a.role, a.grants, route) {
		return ErrSurfaceOutOfScope
	}
	return nil
}

// checkSurface est le garde des fonctions de surface qui portent sur un proxy.
func checkSurface(ctx context.Context, db *sql.DB, ref string, write bool) error {
	return newSurfaceAccess(ctx, db).check(ref, write)
}

// visibleSummaries ne garde que les proxys que l'utilisateur peut voir.
func (a surfaceAccess) visibleSummaries(list []surface.Summary) []surface.Summary {
	out := make([]surface.Summary, 0, len(list))
	for _, s := range list {
		if a.check(s.Route, false) == nil {
			out = append(out, s)
		}
	}
	return out
}
