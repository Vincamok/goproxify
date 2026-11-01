// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import "context"

// Périmètre de la topologie (ADR 0022, section 2) : les droits se donnent sur des groupes de passerelles. Un compte voit
// les groupes que son accès à l'infrastructure désigne (infra:read), et ceux qui servent les proxys, conteneurs, logs ou
// métriques qu'il peut lire : il voit où tourne ce qu'il gère. Une passerelle isolée est un groupe d'un membre ; un Agent
// suit la passerelle qui le tient.

// NodeScope dit quelles passerelles un appelant voit.
type NodeScope struct {
	all    bool
	groups map[string]bool
	infra  Filter
	source ArchitectureGroups
}

// All : toute la topologie est visible.
func (n NodeScope) All() bool { return n.all }

// NodeScopeFor résout les groupes visibles de l'appelant.
func NodeScopeFor(ctx context.Context, c *Caller) NodeScope {
	if c == nil || c.IsAdmin() {
		return NodeScope{all: true}
	}
	infra := c.Filter("infra:read")
	if infra.All() {
		return NodeScope{all: true}
	}
	defaultGroups.mu.Lock()
	source := defaultGroups.source
	defaultGroups.mu.Unlock()
	ns := NodeScope{groups: map[string]bool{}, infra: infra, source: source}
	groups := currentGroups()
	if groups == nil {
		return ns
	}
	routes := currentRoutes(ctx)
	for _, permission := range []string{"proxies:read", "containers:read", "logs:read", "dashboard:read"} {
		f := c.Filter(permission)
		if f.None() {
			continue
		}
		for i := range routes {
			if !f.AllowsRoute(&routes[i], groups) {
				continue
			}
			for _, g := range groups.GroupsServing(&routes[i]) {
				ns.groups[g.Name] = true
			}
		}
	}
	return ns
}

// Group dit si le groupe est visible (par nom ou par son accès à l'infrastructure).
func (n NodeScope) Group(g GroupRef) bool {
	if n.all {
		return true
	}
	return n.groups[g.Name] || n.infra.Allows(Resource{Groups: []GroupRef{g}})
}

// Edge dit si la passerelle (par nom ou identifiant) est visible.
func (n NodeScope) Edge(ref string) bool {
	if n.all {
		return true
	}
	if ref == "" || n.source.Store == nil {
		return false
	}
	g, ok := n.source.GroupOfNode(ref)
	return ok && n.Group(g)
}

// GroupOfNode rend le groupe (avec ses attributs) d'une passerelle désignée par son nom ou son identifiant ; une
// passerelle sans groupe est un groupe d'un membre qui porte son nom.
func (a ArchitectureGroups) GroupOfNode(ref string) (GroupRef, bool) {
	if a.Store == nil {
		return GroupRef{}, false
	}
	nodes, err := a.Store.List()
	if err != nil {
		return GroupRef{}, false
	}
	for _, n := range nodes {
		if n.Role != "edge" || (n.ID != ref && n.Name != ref) {
			continue
		}
		if name := n.Group(); name != "" {
			attrs := a.Store.GroupAttributesOf(name)
			return GroupRef{Name: name, Environment: attrs.Environment, Region: attrs.Region, Tags: attrs.Tags}, true
		}
		return GroupRef{Name: n.Name, Environment: n.Environment, Region: n.Region}, true
	}
	return GroupRef{}, false
}

// GroupNamed dit si le groupe HA de ce nom est visible.
func (n NodeScope) GroupNamed(name string) bool {
	if n.all {
		return true
	}
	if n.groups[name] {
		return true
	}
	if n.source.Store == nil {
		return false
	}
	attrs := n.source.Store.GroupAttributesOf(name)
	return n.infra.Allows(Resource{Groups: []GroupRef{{Name: name, Environment: attrs.Environment, Region: attrs.Region, Tags: attrs.Tags}}})
}
