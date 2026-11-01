// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"regexp"
	"sort"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// Les commandes de premier niveau sont les « case » du commutateur de main() sur os.Args[1].
func registeredCommands(t *testing.T) map[string]bool {
	t.Helper()
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	body := string(src)
	start := strings.Index(body, "switch os.Args[1] {")
	if start < 0 {
		t.Fatal("le commutateur de main() sur os.Args[1] est introuvable")
	}
	body = body[start:]
	if end := strings.Index(body, "\n\t}\n"); end > 0 {
		body = body[:end]
	}
	commands := map[string]bool{}
	re := regexp.MustCompile(`(?m)^\tcase "([a-z][a-z-]*)":`)
	for _, m := range re.FindAllStringSubmatch(body, -1) {
		commands[m[1]] = true
	}
	if len(commands) < 20 {
		t.Fatalf("%d commandes reconnues seulement : le motif ne correspond plus à main.go", len(commands))
	}
	return commands
}

// Une commande ajoutée au commutateur de main.go sans déclaration dans commandDeclarations (rights.go) fait échouer
// la CI : elle doit dire quelles permissions du catalogue ses appels d'API exigent.
func TestEveryCommandDeclaresItsRights(t *testing.T) {
	commands := registeredCommands(t)
	var missing, orphan []string
	for c := range commands {
		if _, ok := commandDeclarations[c]; !ok {
			missing = append(missing, c)
		}
	}
	for c := range commandDeclarations {
		if !commands[c] {
			orphan = append(orphan, c)
		}
	}
	sort.Strings(missing)
	sort.Strings(orphan)
	if len(missing) > 0 {
		t.Errorf("commandes sans déclaration de droits : %v — les ajouter à commandDeclarations (rights.go)", missing)
	}
	if len(orphan) > 0 {
		t.Errorf("déclarations de droits sans commande : %v", orphan)
	}
}

func TestCommandDeclarationsUseCataloguePermissions(t *testing.T) {
	for name, decl := range commandDeclarations {
		if decl.Kind == commandAPI && len(decl.Permissions) == 0 {
			t.Errorf("%s : une commande d'API déclare les permissions qu'elle exige", name)
		}
		if decl.Kind != commandAPI && len(decl.Permissions) > 0 {
			t.Errorf("%s : une commande %q ne déclare pas de permission", name, decl.Kind)
		}
		for _, id := range decl.Permissions {
			if _, ok := rbac.PermissionByID(id); !ok {
				t.Errorf("%s : permission %q absente du catalogue", name, id)
			}
		}
	}
}
