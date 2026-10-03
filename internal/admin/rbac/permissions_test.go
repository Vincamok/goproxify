// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rbac_test

import (
	"context"
	"path/filepath"
	"slices"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// gdpr:reveal se détient par le rôle (superadmin, dpo), en propre ou via une équipe — et
// jamais par le seul rôle admin.
func TestGDPRRevealHolders(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('sa','sa@t','x','superadmin'), ('a','a@t','x','admin'),
			('dpo','dpo@t','x','dpo'), ('direct','d@t','x','user'), ('member','m@t','x','user'), ('plain','p@t','x','user')`,
		`INSERT INTO user_permissions (user_id, permission) VALUES ('direct','gdpr:reveal')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique'), ('ops','Ops')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('legal','member'), ('ops','plain'), ('ops','a')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	ctx := context.Background()
	for user, want := range map[string]bool{"sa": true, "dpo": true, "direct": true, "member": true, "a": false, "plain": false} {
		if got := rbac.HasPermission(ctx, db, user, rbac.PermGDPRReveal); got != want {
			t.Errorf("%s : HasPermission = %v, attendu %v", user, got, want)
		}
		if got := slices.Contains(rbac.AvailableScopesForUser(ctx, db, user), rbac.ScopeGDPRReveal); got != want {
			t.Errorf("%s : gdpr:reveal dans AvailableScopesForUser = %v, attendu %v", user, got, want)
		}
		if got := rbac.IsProtectedAccount(ctx, db, user); got != want {
			t.Errorf("%s : IsProtectedAccount = %v, attendu %v", user, got, want)
		}
	}
	// Un dpo reste un compte user pour le reste : pas d'écriture admin.
	if slices.Contains(rbac.AvailableScopesForUser(ctx, db, "dpo"), rbac.ScopeLogsWrite) || rbac.IsAdmin(ctx, db, "dpo") {
		t.Error("le rôle dpo ne doit pas porter de droits admin")
	}
}

func TestNormalizePermissions(t *testing.T) {
	if got, ok := rbac.NormalizePermissions([]string{"gdpr:reveal", "gdpr:reveal"}); !ok || !slices.Equal(got, []string{"gdpr:reveal"}) {
		t.Fatalf("doublon : %v %v", got, ok)
	}
	if _, ok := rbac.NormalizePermissions([]string{"logs:write"}); ok {
		t.Fatal("permission inconnue acceptée")
	}
	if got, ok := rbac.NormalizePermissions(nil); !ok || got != nil {
		t.Fatalf("vide : %v %v", got, ok)
	}
}
