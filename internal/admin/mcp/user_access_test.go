// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"testing"

	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// get_user_access dit d'où vient chaque droit : un utilisateur reçoit les accès de ses équipes, un administrateur est global.
func TestGetUserAccessTool(t *testing.T) {
	h := setupMCPDB(t)
	r := adminRequest(t, h)
	requestAs(t, h, "ops", "user", "*.example.com")
	requestAs(t, h, "boss", "admin", "*.example.com")

	res, err := h.toolGetUserAccess(r, "ops")
	if err != nil {
		t.Fatal(err)
	}
	acc := res.(rbac.Access)
	if acc.Global || len(acc.Grants) != 1 || acc.Grants[0].Value != "*.example.com" || acc.Grants[0].AccessMode != "write" {
		t.Fatalf("accès d'un utilisateur : %+v", acc)
	}
	res, err = h.toolGetUserAccess(r, "boss")
	if err != nil {
		t.Fatal(err)
	}
	if acc := res.(rbac.Access); !acc.Global || len(acc.Grants) != 0 {
		t.Fatalf("un administrateur est global, ses équipes n'ajoutent aucun accès : %+v", acc)
	}
	if _, err := h.toolGetUserAccess(r, "absent"); err == nil {
		t.Fatal("compte inconnu : erreur attendue")
	}
	if _, err := h.toolGetUserAccess(r, ""); err == nil {
		t.Fatal("id requis")
	}
}
