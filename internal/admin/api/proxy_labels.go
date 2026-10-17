// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"strings"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/labels"
)

// LabelPair est un label tel que le montre l'API ; un secret y apparaît sous la forme ${VARIABLE}.
type LabelPair struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// ProxyLabels est l'équivalent en labels d'un proxy, prêt à copier dans chaque format.
type ProxyLabels struct {
	Labels      []LabelPair              `json:"labels"`
	Env         []string                 `json:"env"`
	Unsupported []string                 `json:"unsupported"`
	Formats     map[string]labels.Output `json:"formats"`
}

// BuildProxyLabels transforme la configuration d'un proxy en labels. Ne lit que la route : aucun secret n'en sort
// (les valeurs sensibles deviennent des variables).
func BuildProxyLabels(config json.RawMessage) (*ProxyLabels, error) {
	var route router.Route
	if err := json.Unmarshal(config, &route); err != nil {
		return nil, err
	}
	if strings.EqualFold(string(route.Type), "https") {
		route.Type = router.RouteHTTP
		route.TLSEnabled = true
	}
	g := labels.FromRoute(&route)
	out := &ProxyLabels{
		Labels:      make([]LabelPair, 0, len(g.Labels)),
		Env:         append([]string{}, g.Env()...),
		Unsupported: append([]string{}, g.Unsupported...),
		Formats:     map[string]labels.Output{},
	}
	for _, p := range g.Labels {
		v := p.Value
		for _, name := range labels.EnvTokens(v) {
			v = strings.ReplaceAll(v, "{{env:"+name+"}}", "${"+name+"}")
		}
		out.Labels = append(out.Labels, LabelPair{Key: p.Key, Value: v})
	}
	for _, f := range labels.Formats {
		o, err := g.Render(f, true)
		if err != nil {
			return nil, err
		}
		out.Formats[string(f)] = o
	}
	// Portainer sans stack.env : tout dans le texte, les secrets à remplacer.
	inline, err := g.Render(labels.FormatPortainer, false)
	if err != nil {
		return nil, err
	}
	out.Formats["portainer_inline"] = inline
	return out, nil
}

// labelsFiles : GET /api/v1/proxies/{id}/labels.
func (h *ProxiesHandler) labelsFiles(w http.ResponseWriter, r *http.Request, id string) {
	env, err := h.fetchProd(r.Context(), id)
	if err != nil {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	if env.Implicit {
		writeErr(w, r, http.StatusConflict, "api.err.labels_implicit")
		return
	}
	var route router.Route
	_ = json.Unmarshal(env.Config, &route)
	route.ID = id
	if !rbac.CanReadProxy(r.Context(), h.DB, auth.UserIDFromContext(r.Context()), &route) {
		writeErr(w, r, http.StatusNotFound, "api.err.proxy_not_found")
		return
	}
	out, err := BuildProxyLabels(env.Config)
	if err != nil {
		writeErr(w, r, http.StatusUnprocessableEntity, "api.err.json_body")
		return
	}
	jsonOK(w, out)
}
