// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

var routeRegistration = regexp.MustCompile(`^\s*mux\.Handle(?:Func)?\(("(?:[^"\\]|\\.)*"|"GET "\+basemapRoute)\s*,\s*(.*)$`)

// registeredRoutes lit server.go : motif de chaque mux.Handle(…) avec le nom de l'enveloppe qui protège le handler.
func registeredRoutes(t *testing.T) map[string]string {
	t.Helper()
	src, err := os.ReadFile("server.go")
	if err != nil {
		t.Fatal(err)
	}
	routes := map[string]string{}
	calls := strings.Count(string(src), "mux.Handle")
	for _, line := range strings.Split(string(src), "\n") {
		m := routeRegistration.FindStringSubmatch(line)
		if m == nil {
			continue
		}
		pattern := m[1]
		if pattern == `"GET "+basemapRoute` {
			pattern = "GET /map/basemap.pmtiles"
		} else {
			pattern = strings.Trim(pattern, `"`)
		}
		wrapper := "none"
		for _, w := range []string{"protected(", "adminOnly(", "adminWrites(", "operatorWrites(", "gatedReads(", "gatedOpen(", "auth.RequireBearerToken(", "auth.RequirePAT("} {
			if strings.HasPrefix(m[2], w) {
				wrapper = strings.TrimSuffix(w, "(")
			}
		}
		routes[pattern] = wrapper
	}
	if len(routes) == 0 {
		t.Fatal("aucune route trouvée : le motif ne correspond plus à server.go")
	}
	if calls != len(routes) {
		t.Fatalf("server.go contient %d appels mux.Handle mais %d routes ont été reconnues : un motif doit être un littéral au début de la ligne pour pouvoir être déclaré", calls, len(routes))
	}
	return routes
}

var wrapperKinds = map[string][]routeKind{
	"none":                    {kindPublic, kindStatic, kindSecret},
	"auth.RequireBearerToken": {kindGateway},
	"auth.RequirePAT":         {kindMCP},
	"protected":               {kindService, kindSelf},
	"adminOnly":               {kindService},
	"adminWrites":             {kindService},
	"operatorWrites":          {kindService},
	"gatedReads":              {kindService},
	"gatedOpen":               {kindService},
}

// Toute route déclare ses droits dans routeDeclarations (rights.go) : une route ajoutée sans déclaration fait échouer
// la CI, comme une déclaration devenue orpheline.
func TestEveryRouteDeclaresItsRights(t *testing.T) {
	routes := registeredRoutes(t)

	var missing, orphan []string
	for pattern := range routes {
		if _, ok := routeDeclarations[pattern]; !ok {
			missing = append(missing, pattern)
		}
	}
	for pattern := range routeDeclarations {
		if _, ok := routes[pattern]; !ok {
			orphan = append(orphan, pattern)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphan)
	if len(missing) > 0 {
		t.Errorf("routes sans déclaration de droits : %v — les ajouter à routeDeclarations (rights.go) avec leur service et leur permission, et au catalogue (rbac.Services) si le service est nouveau", missing)
	}
	if len(orphan) > 0 {
		t.Errorf("déclarations de droits sans route : %v — les retirer de routeDeclarations", orphan)
	}
}

func TestRouteDeclarationsMatchTheirWrapperAndTheCatalogue(t *testing.T) {
	routes := registeredRoutes(t)
	for pattern, wrapper := range routes {
		decl, ok := routeDeclarations[pattern]
		if !ok {
			continue
		}
		allowed := wrapperKinds[wrapper]
		okKind := false
		for _, k := range allowed {
			okKind = okKind || k == decl.Kind
		}
		if !okKind {
			t.Errorf("%s : enveloppe %s incompatible avec la nature déclarée %q (attendu : %v)", pattern, wrapper, decl.Kind, allowed)
			continue
		}
		if decl.Kind != kindService {
			if decl.Service != "" || decl.Read != "" || decl.Write != "" || decl.Delete != "" {
				t.Errorf("%s : une route %q ne déclare ni service ni permission", pattern, decl.Kind)
			}
			continue
		}
		if _, ok := rbac.ServiceByID(decl.Service); !ok {
			t.Errorf("%s : service %q absent du catalogue", pattern, decl.Service)
		}
		if decl.Read == "" && decl.Write == "" {
			t.Errorf("%s : aucune permission déclarée", pattern)
		}
		for _, id := range []string{decl.Read, decl.Write, decl.Delete} {
			if id == "" {
				continue
			}
			p, ok := rbac.PermissionByID(id)
			if !ok {
				t.Errorf("%s : permission %q absente du catalogue", pattern, id)
				continue
			}
			if p.Service != decl.Service && !decl.Mixed {
				t.Errorf("%s : la permission %q appartient au service %q, pas à %q (route mixte : Mixed: true)", pattern, id, p.Service, decl.Service)
			}
		}
		if decl.Mixed && decl.Note == "" {
			t.Errorf("%s : une route mixte dit en Note ce qu'elle mêle", pattern)
		}
	}
}

// La permission déclarée doit couvrir le scope de jeton que rbac.RequiredScopeForRequest exige aujourd'hui pour la
// même requête : la déclaration décrit le contrôle en place, elle ne le contredit pas.
func TestDeclaredPermissionsCoverTheScopeRequiredToday(t *testing.T) {
	for pattern, decl := range routeDeclarations {
		if decl.Kind != kindService {
			continue
		}
		method, path := "", pattern
		if i := strings.Index(pattern, " "); i > 0 {
			method, path = pattern[:i], pattern[i+1:]
		}
		path = strings.NewReplacer("{token}", "x", "{name}", "x").Replace(path)
		type probe struct{ method, permission string }
		var probes []probe
		switch method {
		case "":
			probes = []probe{{http.MethodGet, decl.Read}, {http.MethodPost, decl.Write}}
			if decl.Delete != "" {
				probes = append(probes, probe{http.MethodDelete, decl.Delete})
			}
		case http.MethodGet:
			probes = []probe{{method, decl.Read}}
		default:
			probes = []probe{{method, decl.Write}}
		}
		for _, p := range probes {
			if p.permission == "" {
				continue
			}
			req, _ := http.NewRequest(p.method, path, nil)
			scope := rbac.RequiredScopeForRequest(req)
			if scope == "" {
				continue
			}
			perm, ok := rbac.PermissionByID(p.permission)
			if ok && !perm.CoversPATScope(scope) {
				t.Errorf("%s %s : exige aujourd'hui le scope %q, que %s ne couvre pas (%v)", p.method, path, scope, p.permission, perm.PAT)
			}
		}
	}
}
