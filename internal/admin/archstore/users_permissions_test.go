// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"context"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// users.yaml recharge une base vide : le droit de révélation accordé en propre ou à une équipe
// doit y survivre, comme le rôle dpo.
func TestUsersArchiveKeepsPermissions(t *testing.T) {
	src, err := admindb.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('dpo','dpo@t','x','dpo'), ('direct','d@t','x','user')`,
		`INSERT INTO user_permissions (user_id, permission) VALUES ('direct','gdpr:reveal')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
	} {
		if _, err := src.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	dir := t.TempDir()
	ctx := context.Background()
	if err := NewUserStore(dir).SyncFromDB(ctx, src); err != nil {
		t.Fatal(err)
	}
	dst, err := admindb.Open(filepath.Join(t.TempDir(), "dst.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer dst.Close()
	if err := NewUserStore(dir).LoadIntoDB(ctx, dst); err != nil {
		t.Fatal(err)
	}
	var role string
	var userPerms, teamPerms int
	dst.QueryRow(`SELECT role FROM users WHERE id='dpo'`).Scan(&role)                                                          //nolint:errcheck
	dst.QueryRow(`SELECT COUNT(*) FROM user_permissions WHERE user_id='direct' AND permission='gdpr:reveal'`).Scan(&userPerms) //nolint:errcheck
	dst.QueryRow(`SELECT COUNT(*) FROM team_permissions WHERE team_id='legal' AND permission='gdpr:reveal'`).Scan(&teamPerms)  //nolint:errcheck
	if role != "dpo" || userPerms != 1 || teamPerms != 1 {
		t.Fatalf("après rechargement : role=%q user_permissions=%d team_permissions=%d", role, userPerms, teamPerms)
	}
}
