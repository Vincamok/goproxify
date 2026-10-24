// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"errors"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/archstore"
)

type fakeGroups map[string]string

func (g fakeGroups) GroupOf(ref string) string                          { return g[ref] }
func (fakeGroups) GroupMembers(string) []archstore.NodeEntry            { return nil }
func (fakeGroups) Groups() ([]string, map[string][]archstore.NodeEntry) { return nil, nil }
func (fakeGroups) NodeOf(string) (archstore.NodeEntry, bool)            { return archstore.NodeEntry{}, false }

const portainerRoute = `[{"id":"portainer:1:abc:app.example.fr","host":"app.example.fr","backends":["http://10.0.0.5:80"],"source":"portainer","agent_name":"ag",
 "proxy_config":{"host":"app.example.fr","type":"http","backends":[{"url":"http://10.0.0.5:80"}]}}]`

func TestDiscoveredCarriesDisplayNameAndGroup(t *testing.T) {
	a := fakeDiscoveryEdge(t, portainerRoute, nil)
	b := fakeDiscoveryEdge(t, portainerRoute, nil)
	h := discoveryHandler(t, map[string]string{"goproxify-core": a.URL, "backup": b.URL})
	if _, err := h.DB.Exec(`INSERT INTO nodes (id, node_name, display_name, role) VALUES ('n1','goproxify-core','frontal','edge')`); err != nil {
		t.Fatal(err)
	}
	h.Groups = fakeGroups{"goproxify-core": "prod", "backup": "prod"}

	labels := map[string]string{}
	for _, c := range h.FetchFromEdges(context.Background()) {
		if c.Group != "prod" {
			t.Fatalf("groupe de %s : %q", c.EdgeName, c.Group)
		}
		labels[c.EdgeName] = c.EdgeLabel
	}
	if labels["goproxify-core"] != "frontal" {
		t.Fatalf("le nom affiché doit remplacer le nom de connexion : %v", labels)
	}
	if labels["backup"] != "backup" {
		t.Fatalf("sans nom affiché, le nom de connexion sert de repli : %v", labels)
	}
}

// Les membres d'un groupe HA annoncent la même route : la retrouver sans préciser la passerelle n'est pas ambigu.
func TestFindSameRouteAcrossGroupMembers(t *testing.T) {
	a := fakeDiscoveryEdge(t, portainerRoute, nil)
	b := fakeDiscoveryEdge(t, portainerRoute, nil)
	h := discoveryHandler(t, map[string]string{"edge-a": a.URL, "edge-b": b.URL})

	if _, err := h.Find(context.Background(), "app.example.fr", ""); !errors.Is(err, ErrContainerEdgeRequired) {
		t.Fatalf("sans groupe, la passerelle doit être précisée : %v", err)
	}

	h.Groups = fakeGroups{"edge-a": "prod", "edge-b": "prod"}
	if _, err := h.Find(context.Background(), "app.example.fr", ""); err != nil {
		t.Fatalf("une route de groupe se retrouve sans passerelle : %v", err)
	}

	h.Groups = fakeGroups{"edge-a": "prod", "edge-b": "autre"}
	if _, err := h.Find(context.Background(), "app.example.fr", ""); !errors.Is(err, ErrContainerEdgeRequired) {
		t.Fatalf("deux groupes différents restent ambigus : %v", err)
	}
}
