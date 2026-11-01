// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"context"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// users.yaml recharge une base vide : les capacités d'une équipe et sa composition y survivent, ainsi que l'équipe
// intégrée du DPO. Le compte ne porte ni accès ni capacité en propre.
func TestUsersArchiveKeepsTeamCapabilities(t *testing.T) {
	src, err := admindb.Open(filepath.Join(t.TempDir(), "src.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer src.Close()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('dpo','dpo@t','x','user'), ('other','o@t','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('team-dpo','DPO'), ('legal','Juridique')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('team-dpo','gdpr:reveal'), ('team-dpo','gdpr:erase'), ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('team-dpo','dpo')`,
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
	var member, dpoPerms, legalPerms int
	dst.QueryRow(`SELECT COUNT(*) FROM team_members WHERE team_id='team-dpo' AND user_id='dpo'`).Scan(&member)              //nolint:errcheck
	dst.QueryRow(`SELECT COUNT(*) FROM team_permissions WHERE team_id='team-dpo'`).Scan(&dpoPerms)                         //nolint:errcheck
	dst.QueryRow(`SELECT COUNT(*) FROM team_permissions WHERE team_id='legal' AND permission='gdpr:reveal'`).Scan(&legalPerms) //nolint:errcheck
	if member != 1 || dpoPerms != 2 || legalPerms != 1 {
		t.Fatalf("après rechargement : membre DPO=%d capacités DPO=%d capacité Juridique=%d", member, dpoPerms, legalPerms)
	}
}
