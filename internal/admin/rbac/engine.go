// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"context"
	"database/sql"
	"slices"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// GroupCatalog dit quels groupes de passerelles servent une route : ceux dont une passerelle reçoit cette route
// d'après son jeton (même règle que FilterRoutesByScopes). C'est le lien qui donne un sens au critère « groupe ».
type GroupCatalog interface {
	GroupsServing(route *router.Route) []GroupRef
}

// ArchitectureGroups lit les groupes dans architecture.json (la source de vérité des nœuds). Une passerelle sans
// groupe est un groupe d'un membre qui porte son propre nom (ADR 0014).
type ArchitectureGroups struct{ Store *archstore.Store }

type groupSnapshot struct{ groups []snapshotGroup }

type snapshotGroup struct {
	ref     GroupRef
	members []snapshotMember
}

type snapshotMember struct {
	role   string
	scopes []Scope
}

// Snapshot fige les groupes en une seule lecture du fichier ; à prendre une fois par requête avant de juger une liste.
func (a ArchitectureGroups) Snapshot() GroupCatalog {
	nodes, err := a.Store.List()
	if err != nil {
		return &groupSnapshot{}
	}
	byName := map[string]*snapshotGroup{}
	var order []string
	for _, n := range nodes {
		if n.Role != "edge" {
			continue
		}
		name := n.Group()
		if name == "" {
			name = n.Name
		}
		g, ok := byName[name]
		if !ok {
			ref := GroupRef{Name: name}
			if n.Group() != "" {
				attrs := a.Store.GroupAttributesOf(name)
				ref.Environment, ref.Region, ref.Tags = attrs.Environment, attrs.Region, attrs.Tags
			} else {
				ref.Environment, ref.Region = n.Environment, n.Region
			}
			g = &snapshotGroup{ref: ref}
			byName[name] = g
			order = append(order, name)
		}
		role := n.RBACRole
		if role == "" {
			role = "admin"
		}
		m := snapshotMember{role: role}
		for _, s := range n.Scopes {
			m.scopes = append(m.scopes, Scope{Type: s.Type, Value: s.Value})
		}
		g.members = append(g.members, m)
	}
	out := &groupSnapshot{}
	for _, name := range order {
		out.groups = append(out.groups, *byName[name])
	}
	return out
}

// GroupsServing rend, dans l'ordre des groupes, ceux dont un membre reçoit la route.
func (s *groupSnapshot) GroupsServing(route *router.Route) []GroupRef {
	var out []GroupRef
	for _, g := range s.groups {
		for _, m := range g.members {
			if RouteAllowedByToken(m.role, m.scopes, route) {
				out = append(out, g.ref)
				break
			}
		}
	}
	return out
}

// Filter est le périmètre à appliquer à une liste pour une permission : tout, rien, ou l'union des périmètres des
// accès de l'appelant qui portent la permission.
type Filter struct {
	all        bool
	perimeters []Perimeter
}

// All : l'appelant voit tout (administrateur, ou accès sans critère).
func (f Filter) All() bool { return f.all }

// None : l'appelant ne voit rien.
func (f Filter) None() bool { return !f.all && len(f.perimeters) == 0 }

// NeedsGroups dit si un périmètre juge les groupes ; sinon inutile de les résoudre pour chaque ligne.
func (f Filter) NeedsGroups() bool {
	return slices.ContainsFunc(f.perimeters, func(p Perimeter) bool { return !p.Group.empty() })
}

// Allows juge une ressource dont les groupes sont déjà résolus.
func (f Filter) Allows(res Resource) bool {
	if f.all {
		return true
	}
	return slices.ContainsFunc(f.perimeters, func(p Perimeter) bool { return p.Matches(res) })
}

// AllowsRoute juge un proxy ; groups n'est lu que si un périmètre juge les groupes.
func (f Filter) AllowsRoute(route *router.Route, groups GroupCatalog) bool {
	if f.all {
		return true
	}
	var gs []GroupRef
	if groups != nil && f.NeedsGroups() {
		gs = groups.GroupsServing(route)
	}
	return f.Allows(RouteResource(route, gs))
}

// accessRule est un accès d'équipe réduit à ce que le moteur juge : un périmètre et si l'écriture est permise.
type accessRule struct {
	perimeter Perimeter
	write     bool
}

// Engine répond « cette personne peut-elle faire ceci sur cet objet ? » (Can) et « sur quoi peut-elle le faire ? »
// (Scope). Tant que les accès à grille de niveaux n'existent pas (ADR 0022, livraison 3), il lit les accès d'équipe
// actuels, qui sont chacun un critère unique en lecture ou en écriture.
type Engine struct{ DB *sql.DB }

// legacyServices sont les services que les accès d'équipe actuels (type, valeur, mode) savent porter : les proxys et
// ce qui en dépend. Les autres restent à l'administrateur jusqu'à la grille de niveaux.
var legacyServices = []string{"proxies", "containers", "surface", "domains"}

// required dit ce que l'accès actuel doit porter pour la permission : (lecture, true) ou (écriture, true) ; false si
// aucun accès d'équipe actuel ne la donne (destructive, sensible, plateforme, service hors des accès actuels).
func required(permission string) (write, ok bool) {
	p, found := PermissionByID(permission)
	if !found || !slices.Contains(legacyServices, p.Service) {
		return false, false
	}
	if p.Class != ClassOrdinary {
		return false, false
	}
	svc, _ := ServiceByID(p.Service)
	if p.ID == svc.ID+":"+svc.Levels[0].ID {
		return false, true
	}
	return true, true
}

func (e Engine) rules(ctx context.Context, userID string) ([]accessRule, error) {
	grants, err := UserEffectiveGrants(ctx, e.DB, userID)
	if err != nil {
		return nil, err
	}
	rules := make([]accessRule, 0, len(grants))
	for _, g := range grants {
		rule := accessRule{write: g.Mode == AccessWrite}
		switch g.Type {
		case "domain":
			rule.perimeter.Domain = g.Value
		case "proxy":
			rule.perimeter.Proxy = g.Value
		case "server":
			rule.perimeter.Backend = g.Value
		case "edge":
			rule.perimeter.Group.Name = g.Value
		default:
			continue
		}
		rules = append(rules, rule)
	}
	return rules, nil
}

// Scope rend le périmètre qu'il faut appliquer à une liste pour la permission demandée.
func (e Engine) Scope(ctx context.Context, userID, permission string) Filter {
	if IsAdmin(ctx, e.DB, userID) {
		return Filter{all: true}
	}
	write, ok := required(permission)
	if !ok {
		return Filter{}
	}
	rules, err := e.rules(ctx, userID)
	if err != nil {
		return Filter{}
	}
	var f Filter
	for _, r := range rules {
		if write && !r.write {
			continue
		}
		if r.perimeter.IsEmpty() {
			return Filter{all: true}
		}
		f.perimeters = append(f.perimeters, r.perimeter)
	}
	return f
}

// Can dit si la personne a la permission sur la ressource.
func (e Engine) Can(ctx context.Context, userID, permission string, res Resource) bool {
	return e.Scope(ctx, userID, permission).Allows(res)
}

// CanRoute dit si la personne a la permission sur un proxy ; groups n'est lu que si son accès juge les groupes.
func (e Engine) CanRoute(ctx context.Context, userID, permission string, route *router.Route, groups GroupCatalog) bool {
	return e.Scope(ctx, userID, permission).AllowsRoute(route, groups)
}
