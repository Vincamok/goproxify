// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"encoding/json"
	"sort"

	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// GroupEntry retient, pour un groupe HA, la version de sa fiche et l'empreinte du contenu de cette version
// (ADR 0014, section 3). La composition elle-même se déduit des nœuds (config.cluster_group) : la fiche en est la
// projection que les passerelles gardent, et ce qui permet de reconstituer le fichier si l'Admin est perdu.
type GroupEntry struct {
	Name    string `json:"name"`
	Version int64  `json:"version"`
	Hash    string `json:"hash,omitempty"`
}

// GroupCardVersion rend la version et l'empreinte retenues pour le groupe (0 et "" s'il n'en a pas encore).
func (s *Store) GroupCardVersion(name string) (int64, string) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	arch, err := s.readLocked()
	if err != nil {
		return 0, ""
	}
	for _, g := range arch.Groups {
		if g.Name == name {
			return g.Version, g.Hash
		}
	}
	return 0, ""
}

// SetGroupCard retient la version et l'empreinte de la fiche d'un groupe. Une version plus basse que celle du fichier
// n'est pas retenue.
func (s *Store) SetGroupCard(name string, version int64, hash string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return err
	}
	setGroupEntry(arch, GroupEntry{Name: name, Version: version, Hash: hash})
	return s.writeLocked(arch)
}

func setGroupEntry(arch *Architecture, g GroupEntry) {
	for i := range arch.Groups {
		if arch.Groups[i].Name == g.Name {
			if g.Version >= arch.Groups[i].Version {
				arch.Groups[i] = g
			}
			return
		}
	}
	arch.Groups = append(arch.Groups, g)
	sort.Slice(arch.Groups, func(i, j int) bool { return arch.Groups[i].Name < arch.Groups[j].Name })
}

// RecoverReport dit ce qu'une reconstitution a ajouté au fichier.
type RecoverReport struct {
	Groups  []string `json:"groups"`
	Nodes   int      `json:"nodes"`
	Joined  int      `json:"joined"` // passerelles déjà connues, sans config, qui ont rejoint leur groupe
	Domains int      `json:"domains"`
	Skipped int      `json:"skipped"` // entrées déjà présentes, laissées telles quelles
}

// MergeCards complète le fichier avec le contenu de fiches de groupe : les membres et les domaines qu'il ne connaît pas
// sont ajoutés ; un nœud qu'il connaît (même identifiant, ou même nom) reste tel quel, sauf s'il n'a aucune config : il rejoint alors son groupe. La version
// d'un groupe retenue est la plus haute vue. Pour chaque groupe, la fiche de version la plus haute fournie fait foi.
func (s *Store) MergeCards(cards []edgews.GroupCard) (RecoverReport, error) {
	best := map[string]edgews.GroupCard{}
	for _, c := range cards {
		if c.Group == "" {
			continue
		}
		if cur, ok := best[c.Group]; !ok || c.Version > cur.Version {
			best[c.Group] = c
		}
	}
	names := make([]string, 0, len(best))
	for g := range best {
		names = append(names, g)
	}
	sort.Strings(names)

	s.mu.Lock()
	defer s.mu.Unlock()
	arch, err := s.readLocked()
	if err != nil {
		return RecoverReport{}, err
	}
	rep := RecoverReport{Groups: names}
	for _, g := range names {
		c := best[g]
		for _, m := range c.Members {
			if m.ID == "" && m.Name == "" {
				continue
			}
			cfg, _ := json.Marshal(map[string]any{"cluster": true, "cluster_group": g})
			if i := nodeIndex(arch, m.ID, m.Name); i >= 0 {
				// Une passerelle appairée avant la reconstitution n'a pas de config : elle rejoint son groupe. Une config
				// déjà déclarée n'est pas touchée.
				if len(arch.Nodes[i].Config) == 0 {
					arch.Nodes[i].Config = cfg
					rep.Joined++
				} else {
					rep.Skipped++
				}
				continue
			}
			arch.Nodes = append(arch.Nodes, NodeEntry{ID: m.ID, Role: "edge", Name: m.Name, Endpoint: m.Endpoint, Config: cfg})
			rep.Nodes++
		}
		for _, d := range c.Domains {
			if domainKnown(arch, d.ID, d.Domain) {
				rep.Skipped++
				continue
			}
			arch.Domains = append(arch.Domains, DomainEntry{
				ID: d.ID, Domain: d.Domain, EdgeID: d.EdgeID, DNSProvider: d.DNSProvider, DNSCredentials: d.DNSCredentials,
				CertMethod: d.CertMethod, DelegatedToEdgeID: d.DelegatedToEdgeID, DelegatedEndpoint: d.DelegatedEndpoint,
				DelegationMode: d.DelegationMode,
			})
			rep.Domains++
		}
		setGroupEntry(arch, GroupEntry{Name: g, Version: c.Version})
	}
	if rep.Nodes == 0 && rep.Domains == 0 && len(names) == 0 {
		return rep, nil
	}
	return rep, s.writeLocked(arch)
}

func nodeIndex(arch *Architecture, id, name string) int {
	for i, n := range arch.Nodes {
		if (id != "" && n.ID == id) || (name != "" && n.Name == name) {
			return i
		}
	}
	return -1
}

func domainKnown(arch *Architecture, id, domain string) bool {
	for _, d := range arch.Domains {
		if (id != "" && d.ID == id) || (domain != "" && d.Domain == domain) {
			return true
		}
	}
	return false
}
