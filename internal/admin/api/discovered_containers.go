// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"log/slog"
	"net/http"
	"strings"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// DiscoveredContainersHandler agrège les conteneurs découverts par les Agents
// depuis toutes les passerelles actives via GET /internal/v1/agent/containers.
type DiscoveredContainersHandler struct {
	DB  *sql.DB
	Log *slog.Logger
}

type DiscoveredContainer struct {
	ID           string         `json:"id"`
	Host         string         `json:"host"`
	Aliases      []string       `json:"aliases,omitempty"`
	Backends     []string       `json:"backends"`
	ContainerIDs []string       `json:"container_ids,omitempty"`
	TLS          bool           `json:"tls"`
	Source       string         `json:"source"`
	EdgeName     string         `json:"edge_name"`
	AgentName    string         `json:"agent_name,omitempty"`
	Config       map[string]any `json:"config,omitempty"`
	// ShadowedBy : ID du proxy configuré qui sert l'hôte à la place de la route des labels.
	ShadowedBy string `json:"shadowed_by,omitempty"`
	// Missing : contrôles de sécurité absents de la route (tls, waf, rate_limit), snippets compris.
	Missing []string `json:"missing,omitempty"`
	// ProxyConfig : route complète pour la conversion en proxy ; n'est jamais renvoyée par GET /discovered-containers.
	ProxyConfig json.RawMessage `json:"proxy_config,omitempty"`
}

func (h *DiscoveredContainersHandler) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeErr(w, r, http.StatusMethodNotAllowed, "api.err.method")
		return
	}
	switch strings.TrimPrefix(r.URL.Path, "/api/v1/discovered-containers") {
	case "", "/":
		h.list(w, r)
	case "/detail":
		h.detail(w, r)
	case "/orphans":
		h.orphans(w, r)
	default:
		http.NotFound(w, r)
	}
}

func (h *DiscoveredContainersHandler) list(w http.ResponseWriter, r *http.Request) {
	result := h.FetchFromEdges(r.Context())
	store, _ := loadSnippetStore(r.Context(), h.DB)
	for i := range result {
		if route := routeOf(result[i].ProxyConfig); route != nil {
			result[i].Missing = auditMissing(router.ResolveSnippets(route, store))
		}
		result[i].ProxyConfig = nil
	}
	jsonOK(w, result)
}

// routeOf lit la config de proxy d'une route découverte ; nil si elle est absente ou illisible.
func routeOf(config json.RawMessage) *router.Route {
	if len(config) == 0 {
		return nil
	}
	var route router.Route
	if json.Unmarshal(config, &route) != nil {
		return nil
	}
	return &route
}

var (
	ErrContainerNotFound         = errors.New("conteneur découvert introuvable")
	ErrContainerEdgeRequired     = errors.New("plusieurs passerelles annoncent ce conteneur : précisez la passerelle")
	ErrContainerAlreadyConverted = errors.New("ce conteneur est déjà remplacé par un proxy")
)

// Find retrouve une route découverte (par son ID ou son hôte, sur la passerelle edge si elle est donnée) avec sa config de proxy.
func (h *DiscoveredContainersHandler) Find(ctx context.Context, id, edge string) (*DiscoveredContainer, error) {
	var matches []DiscoveredContainer
	for _, c := range h.FetchFromEdges(ctx) {
		if (c.ID == id || strings.EqualFold(c.Host, id)) && (edge == "" || c.EdgeName == edge) && len(c.ProxyConfig) > 0 {
			matches = append(matches, c)
		}
	}
	switch {
	case len(matches) == 0:
		return nil, ErrContainerNotFound
	case len(matches) > 1:
		return nil, ErrContainerEdgeRequired
	}
	return &matches[0], nil
}

// ForConversion est Find pour une route que rien ne remplace encore.
func (h *DiscoveredContainersHandler) ForConversion(ctx context.Context, id, edge string) (*DiscoveredContainer, error) {
	c, err := h.Find(ctx, id, edge)
	if err != nil {
		return nil, err
	}
	if c.ShadowedBy != "" {
		return nil, ErrContainerAlreadyConverted
	}
	return c, nil
}

// ConversionConfig est la config du proxy créé à partir de la route : l'ID et la date du nouveau proxy, et l'origine
// qui permet de signaler le proxy si le conteneur disparaît.
func (c *DiscoveredContainer) ConversionConfig(proxyID string, updatedAt time.Time) (json.RawMessage, error) {
	var m map[string]any
	if err := json.Unmarshal(c.ProxyConfig, &m); err != nil {
		return nil, err
	}
	m["id"] = proxyID
	m["updated_at"] = updatedAt
	m["origin"] = router.RouteOrigin{ID: c.ID, Edge: c.EdgeName}
	return json.Marshal(m)
}

// FetchFromEdges liste les routes découvertes par les labels (Docker, Kubernetes…) sur toutes les passerelles.
func (h *DiscoveredContainersHandler) FetchFromEdges(ctx context.Context) []DiscoveredContainer {
	items, _ := h.fetchAll(ctx)
	return items
}

// fetchAll liste les routes découvertes et les passerelles qui ont répondu : une passerelle muette n'a pas de liste,
// donc rien ne permet d'y déclarer un conteneur disparu.
func (h *DiscoveredContainersHandler) fetchAll(ctx context.Context) ([]DiscoveredContainer, map[string]bool) {
	rows, err := h.DB.QueryContext(ctx,
		`SELECT node_name, node_endpoint, token FROM tokens
		 WHERE role='edge' AND revoked=0 AND node_endpoint != ''
		   AND (expires_at IS NULL OR expires_at > CURRENT_TIMESTAMP)`)
	if err != nil {
		return []DiscoveredContainer{}, map[string]bool{}
	}
	defer rows.Close()

	type edgeInfo struct{ name, endpoint, token string }
	var edges []edgeInfo
	for rows.Next() {
		var c edgeInfo
		if rows.Scan(&c.name, &c.endpoint, &c.token) == nil && c.endpoint != "" {
			c.token = auth.PlainNodeToken(c.token)
			edges = append(edges, c)
		}
	}

	var mu sync.Mutex
	var result []DiscoveredContainer
	answered := map[string]bool{}
	var wg sync.WaitGroup

	for _, c := range edges {
		wg.Add(1)
		go func(name, ep, tok string) {
			defer wg.Done()
			items, ok := h.fetchContainersFromEdge(ctx, ep, tok)
			for i := range items {
				items[i].EdgeName = name
			}
			mu.Lock()
			result = append(result, items...)
			if ok {
				answered[name] = true
			}
			mu.Unlock()
		}(c.name, c.endpoint, c.token)
	}
	wg.Wait()
	return result, answered
}

func (h *DiscoveredContainersHandler) fetchContainersFromEdge(ctx context.Context, edgeEndpoint, token string) ([]DiscoveredContainer, bool) {
	warn := func(msg string, args ...any) {
		if h.Log != nil {
			h.Log.Warn(msg, args...)
		}
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet,
		edgeEndpoint+"/internal/v1/agent/containers", nil)
	if err != nil {
		warn("discovered-containers: requête invalide", "endpoint", edgeEndpoint, "err", err)
		return nil, false
	}
	req.Header.Set("Authorization", "Bearer "+token)
	resp, err := internalClient.Do(req)
	if err != nil {
		warn("discovered-containers: Passerelle injoignable", "endpoint", edgeEndpoint, "err", err)
		return nil, false
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		warn("discovered-containers: Passerelle a refusé", "endpoint", edgeEndpoint, "status", resp.StatusCode)
		return nil, false
	}
	var items []DiscoveredContainer
	if err := json.NewDecoder(resp.Body).Decode(&items); err != nil {
		warn("discovered-containers: JSON invalide", "endpoint", edgeEndpoint, "err", err)
		return nil, false
	}
	return items, true
}
