// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac

import (
	"slices"
	"strings"
	"testing"
)

func TestCatalogIsConsistent(t *testing.T) {
	if err := ValidateCatalog(); err != nil {
		t.Fatal(err)
	}
}

func TestCatalogCoversTheFourGDPRCapacities(t *testing.T) {
	for _, id := range []string{PermGDPRReveal, PermGDPRExport, PermGDPRErase, PermGDPRHold} {
		p, ok := PermissionByID(id)
		if !ok || p.Service != "gdpr" {
			t.Errorf("%s : absente du service gdpr (%v)", id, ok)
		}
	}
}

// Un outil MCP sans permission déclarée dans le catalogue fait échouer la CI : l'ajouter dans toolPermissionGroups.
func TestEveryMCPToolDeclaresACataloguePermission(t *testing.T) {
	declared := map[string]bool{}
	for _, tool := range mcpTools {
		declared[tool] = true
		perm := ToolPermission(tool)
		if perm == "" {
			t.Errorf("outil MCP %q sans permission déclarée (catalog_tools.go)", tool)
			continue
		}
		p, ok := PermissionByID(perm)
		if !ok {
			t.Errorf("outil %q : permission %q absente du catalogue", tool, perm)
			continue
		}
		if scope := ToolRequiredScope(tool); scope != "" && !p.CoversPATScope(scope) {
			t.Errorf("outil %q : exige le scope %q mais %q ne le couvre pas (%v)", tool, scope, perm, p.PAT)
		}
	}
	for _, g := range toolPermissionGroups {
		for _, tool := range strings.Fields(g.tools) {
			if !declared[tool] {
				t.Errorf("%q est déclaré pour %s mais n'est pas un outil MCP", tool, g.permission)
			}
		}
	}
	seen := map[string]string{}
	for _, g := range toolPermissionGroups {
		for _, tool := range strings.Fields(g.tools) {
			if prev, dup := seen[tool]; dup {
				t.Errorf("outil %q déclaré deux fois (%s et %s)", tool, prev, g.permission)
			}
			seen[tool] = g.permission
		}
	}
}

func TestServiceIDsAreStable(t *testing.T) {
	ids := []string{}
	for _, s := range Services {
		ids = append(ids, s.ID)
	}
	for _, want := range []string{"proxies", "logs", "certs", "alerts", "portal_sessions", "gdpr", "accounts"} {
		if !slices.Contains(ids, want) {
			t.Errorf("service %q absent du catalogue", want)
		}
	}
}
