// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/admin/routesecrets"
	"github.com/vincamok/goproxify/internal/admin/security"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type snippetRef struct{ ID, Type string }

// loadSnippetStore lit les snippets de l'Admin pour juger une route comme la passerelle la verra, snippets fusionnés.
func loadSnippetStore(ctx context.Context, db *sql.DB) (*router.SnippetStore, []snippetRef) {
	store := router.NewSnippetStore()
	if db == nil {
		return store, nil
	}
	rows, err := db.QueryContext(ctx, `SELECT id, type, config FROM snippets ORDER BY name`)
	if err != nil {
		return store, nil
	}
	defer rows.Close()
	var list []*router.Snippet
	var refs []snippetRef
	for rows.Next() {
		var id, typ, cfg string
		if rows.Scan(&id, &typ, &cfg) != nil {
			continue
		}
		list = append(list, &router.Snippet{ID: id, Type: router.SnippetType(typ), Config: json.RawMessage(cfg)})
		refs = append(refs, snippetRef{ID: id, Type: typ})
	}
	store.Replace(list)
	return store, refs
}

// auditMissing liste les contrôles de sécurité de base absents d'une route (snippets déjà fusionnés).
func auditMissing(r *router.Route) []string {
	var missing []string
	if !r.TLSEnabled && !r.TLSPassthrough {
		missing = append(missing, "tls")
	}
	if r.WAF == nil || !r.WAF.Enabled {
		missing = append(missing, "waf")
	}
	if r.RateLimit == nil {
		missing = append(missing, "rate_limit")
	}
	return missing
}

// applySecurityTemplate rend une copie de la route avec les contrôles manquants posés : un snippet de l'Admin du bon
// type s'il en existe un, sinon un réglage par défaut (WAF en blocage, 100 requêtes/s avec rafale de 50).
func applySecurityTemplate(route *router.Route, missing []string, snippets []snippetRef) *router.Route {
	fixed := *route
	fixed.SnippetIDs = append([]string(nil), route.SnippetIDs...)
	useSnippet := func(typ string) bool {
		for _, s := range snippets {
			if s.Type != typ {
				continue
			}
			for _, id := range fixed.SnippetIDs {
				if id == s.ID {
					return true
				}
			}
			fixed.SnippetIDs = append(fixed.SnippetIDs, s.ID)
			return true
		}
		return false
	}
	for _, control := range missing {
		switch control {
		case "tls":
			fixed.TLSEnabled = true
		case "waf":
			if !useSnippet("waf") {
				fixed.WAF = &router.WAFConfig{Enabled: true, Mode: "block"}
			}
		case "rate_limit":
			if !useSnippet("rate_limit") {
				fixed.RateLimit = &router.RateLimitConfig{RequestsPerSecond: 100, Burst: 50}
			}
		}
	}
	return &fixed
}

// ContainerAudit est le bilan de sécurité d'une route découverte et ce qu'il faut ajouter à ses labels pour le combler.
type ContainerAudit struct {
	Score   int              `json:"score"`
	Grade   string           `json:"grade"`
	Checks  []security.Check `json:"checks"`
	Missing []string         `json:"missing"`
	// Added : labels à ajouter ou à changer (modèle de sécurité), absents des labels actuels.
	Added []LabelPair `json:"added"`
}

// ContainerDetail est la vue complète d'une route découverte : config effective, labels qui la reproduisent, bilan.
type ContainerDetail struct {
	Container DiscoveredContainer `json:"container"`
	// Config : la route telle que la passerelle la sert, secrets masqués.
	Config json.RawMessage `json:"config"`
	Labels *ProxyLabels    `json:"labels"`
	// FixedLabels : les mêmes labels avec le modèle de sécurité appliqué ; absent quand rien ne manque.
	FixedLabels *ProxyLabels   `json:"fixed_labels,omitempty"`
	Audit       ContainerAudit `json:"audit"`
}

// Detail construit la vue complète de la route c.
func (h *DiscoveredContainersHandler) Detail(ctx context.Context, c *DiscoveredContainer) (*ContainerDetail, error) {
	route := routeOf(c.ProxyConfig)
	if route == nil {
		return nil, ErrContainerNotFound
	}
	store, snippets := loadSnippetStore(ctx, h.DB)
	resolved := router.ResolveSnippets(route, store)

	current, err := buildRouteLabels(route)
	if err != nil {
		return nil, err
	}
	hc := security.ComputeHeaderScore(c.ID, c.Host, c.Host, *resolved)
	audit := ContainerAudit{
		Score: hc.Score, Grade: hc.Grade, Checks: hc.Checks,
		Missing: auditMissing(resolved), Added: []LabelPair{},
	}
	if audit.Missing == nil {
		audit.Missing = []string{}
	}
	out := &ContainerDetail{
		Container: *c,
		Config:    routesecrets.Mask(c.ProxyConfig, routesecrets.FromDB(h.DB)),
		Labels:    current,
		Audit:     audit,
	}
	out.Container.ProxyConfig = nil
	out.Container.Missing = audit.Missing

	if len(audit.Missing) > 0 {
		fixed, err := buildRouteLabels(applySecurityTemplate(route, audit.Missing, snippets))
		if err != nil {
			return nil, err
		}
		have := map[LabelPair]bool{}
		for _, p := range current.Labels {
			have[p] = true
		}
		for _, p := range fixed.Labels {
			if !have[p] {
				out.Audit.Added = append(out.Audit.Added, p)
			}
		}
		out.FixedLabels = fixed
	}
	return out, nil
}

// detail : GET /api/v1/discovered-containers/detail?id=<id ou hôte>&edge=<passerelle>.
func (h *DiscoveredContainersHandler) detail(w http.ResponseWriter, r *http.Request) {
	c, err := h.Find(r.Context(), r.URL.Query().Get("id"), r.URL.Query().Get("edge"))
	if err != nil {
		writeFindErr(w, r, err)
		return
	}
	out, err := h.Detail(r.Context(), c)
	if err != nil {
		writeFindErr(w, r, err)
		return
	}
	jsonOK(w, out)
}

func writeFindErr(w http.ResponseWriter, r *http.Request, err error) {
	switch err {
	case ErrContainerEdgeRequired:
		writeErr(w, r, http.StatusConflict, "api.err.container_edge_required")
	case ErrContainerNotFound:
		writeErr(w, r, http.StatusNotFound, "api.err.container_not_found")
	default:
		writeErr(w, r, http.StatusUnprocessableEntity, "api.err.json_body")
	}
}

// OrphanProxy est un proxy converti depuis une route découverte qui n'existe plus.
type OrphanProxy struct {
	ProxyID string             `json:"proxy_id"`
	Host    string             `json:"host"`
	Enabled bool               `json:"enabled"`
	Origin  router.RouteOrigin `json:"origin"`
}

// Orphans liste les proxys convertis dont la route d'origine n'est plus annoncée par sa passerelle. Une passerelle qui
// ne répond pas n'a pas de liste à comparer : ses proxys ne sont jamais déclarés orphelins.
func (h *DiscoveredContainersHandler) Orphans(ctx context.Context) ([]OrphanProxy, error) {
	envs, err := edgeproxy.LoadProductionEnvelopes(ctx, h.DB)
	if err != nil {
		return nil, err
	}
	items, answered := h.fetchAll(ctx)
	present := map[[2]string]bool{}
	for _, it := range items {
		present[[2]string{it.EdgeName, it.ID}] = true
	}
	out := []OrphanProxy{}
	for _, env := range envs {
		route := routeOf(env.Config)
		if route == nil || route.Origin == nil || !answered[route.Origin.Edge] {
			continue
		}
		if present[[2]string{route.Origin.Edge, route.Origin.ID}] {
			continue
		}
		host := route.Host
		if host == "" {
			host = env.Host
		}
		out = append(out, OrphanProxy{ProxyID: env.ID, Host: host, Enabled: env.Enabled, Origin: *route.Origin})
	}
	return out, nil
}

// orphans : GET /api/v1/discovered-containers/orphans.
func (h *DiscoveredContainersHandler) orphans(w http.ResponseWriter, r *http.Request) {
	list, err := h.Orphans(r.Context())
	if err != nil {
		writeErr(w, r, http.StatusBadGateway, "api.err.internal")
		return
	}
	jsonOK(w, list)
}
