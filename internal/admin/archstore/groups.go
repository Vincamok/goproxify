// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"encoding/json"
	"sort"
)

// Group retourne le groupe HA d'un nœud, tel que déclaré par le wizard
// (config.cluster = true et config.cluster_group non vide). Vide sinon.
func (n NodeEntry) Group() string {
	if n.Role != "edge" || len(n.Config) == 0 {
		return ""
	}
	var cfg struct {
		Cluster      bool   `json:"cluster"`
		ClusterGroup string `json:"cluster_group"`
	}
	if json.Unmarshal(n.Config, &cfg) != nil || !cfg.Cluster {
		return ""
	}
	return cfg.ClusterGroup
}

// GroupOf retourne le groupe HA de la passerelle désignée par ref (id du nœud ou nom).
// Vide si la passerelle n'appartient à aucun groupe.
func (s *Store) GroupOf(ref string) string {
	if ref == "" {
		return ""
	}
	nodes, err := s.List()
	if err != nil {
		return ""
	}
	for _, n := range nodes {
		if n.ID == ref || n.Name == ref {
			if g := n.Group(); g != "" {
				return g
			}
		}
	}
	return ""
}

// GroupMembers retourne les nœuds du groupe.
func (s *Store) GroupMembers(group string) []NodeEntry {
	if group == "" {
		return nil
	}
	nodes, err := s.List()
	if err != nil {
		return nil
	}
	var out []NodeEntry
	for _, n := range nodes {
		if n.Group() == group {
			out = append(out, n)
		}
	}
	return out
}

// Groups retourne les groupes HA (nom → membres), noms triés.
func (s *Store) Groups() (names []string, members map[string][]NodeEntry) {
	members = map[string][]NodeEntry{}
	nodes, err := s.List()
	if err != nil {
		return nil, members
	}
	for _, n := range nodes {
		if g := n.Group(); g != "" {
			members[g] = append(members[g], n)
		}
	}
	for g := range members {
		names = append(names, g)
	}
	sort.Strings(names)
	return names, members
}

// IsInGroup indique si la passerelle (id ou nom) est membre du groupe.
func (s *Store) IsInGroup(ref, group string) bool {
	return group != "" && s.GroupOf(ref) == group
}

// PortalFlag lit `config.portal` du wizard : le nœud héberge-t-il le portail d'accès ?
// declared est faux quand le wizard ne dit rien (le portail suit alors la config du groupe).
func (n NodeEntry) PortalFlag() (enabled, declared bool) {
	if len(n.Config) == 0 {
		return false, false
	}
	var cfg struct {
		Portal *bool `json:"portal"`
	}
	if json.Unmarshal(n.Config, &cfg) != nil || cfg.Portal == nil {
		return false, false
	}
	return *cfg.Portal, true
}

// NodeOf retourne le nœud désigné par ref (id ou nom).
func (s *Store) NodeOf(ref string) (NodeEntry, bool) {
	if ref == "" {
		return NodeEntry{}, false
	}
	nodes, err := s.List()
	if err != nil {
		return NodeEntry{}, false
	}
	for _, n := range nodes {
		if n.ID == ref || n.Name == ref {
			return n, true
		}
	}
	return NodeEntry{}, false
}
