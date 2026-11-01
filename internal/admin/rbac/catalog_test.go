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

// Chaque profil se valide comme un accès : services, niveaux et permissions existent et sont accordables.
func TestProfilesAreValidAccesses(t *testing.T) {
	ids := map[string]bool{}
	for _, p := range Profiles {
		if ids[p.ID] {
			t.Errorf("profil %q déclaré deux fois", p.ID)
		}
		ids[p.ID] = true
		if err := p.Access().Validate(); err != nil {
			t.Errorf("profil %q : %v", p.ID, err)
		}
	}
}

func TestAccessGrantsAreCumulativeAndExplicitPermissionsAreSeparate(t *testing.T) {
	a := TeamAccess{Levels: map[string]string{"proxies": "operate", "certs": "read"}, Permissions: []string{"certs:deploy"}}
	for perm, want := range map[string]bool{
		"proxies:read": true, "proxies:operate": true, "proxies:manage": false,
		"certs:read": true, "certs:manage": false, "certs:deploy": true, "certs:export_key": false,
		"logs:read": false, "snippets:write": false, "inconnue": false,
	} {
		if got := a.Grants(perm); got != want {
			t.Errorf("Grants(%s) = %v, attendu %v", perm, got, want)
		}
	}
	if (TeamAccess{Permissions: []string{"certs:deploy"}}).Grants("certs:read") {
		t.Error("une permission explicite n'ouvre pas le niveau de lecture")
	}
}

func TestAccessValidateRefusesWhatATeamCannotHold(t *testing.T) {
	for name, a := range map[string]TeamAccess{
		"service inconnu":               {Levels: map[string]string{"inconnu": "read"}},
		"niveau inconnu":                {Levels: map[string]string{"proxies": "dieu"}},
		"écriture d'objet partagé":      {Levels: map[string]string{"snippets": "write"}},
		"capacité RGPD":                 {Permissions: []string{"gdpr:erase"}},
		"accorder des droits":           {Permissions: []string{"teams:write"}},
		"niveau coché comme permission": {Permissions: []string{"proxies:read"}},
		"permission inconnue":           {Permissions: []string{"x:y"}},
		"doublon":                       {Permissions: []string{"certs:deploy", "certs:deploy"}},
		"périmètre invalide":            {Perimeter: Perimeter{Proxy: "re:("}},
	} {
		if err := a.Validate(); err == nil {
			t.Errorf("%s : devrait être refusé", name)
		}
	}
}
