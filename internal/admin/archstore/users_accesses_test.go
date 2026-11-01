// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package archstore

import (
	"context"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// Les accès d'équipe passent par users.yaml : un Admin neuf, démarré sur le même fichier, retrouve leurs périmètres,
// leurs niveaux et leurs cases à cocher.
func TestTeamAccessesSurviveTheUsersArchive(t *testing.T) {
	ctx := context.Background()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('u','u@t','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('t1','prod')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('t1','u')`,
		`INSERT INTO team_accesses (id, team_id, name, perimeter, levels, permissions, position)
		 VALUES ('a1','t1','Exploitation','{"domain":"*.corp.io","labels":{"env":"prod"}}','{"proxies":"operate"}','["certs:deploy"]',1)`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s : %v", q, err)
		}
	}
	dir := t.TempDir()
	store := NewUserStore(dir)
	if err := store.SyncFromDB(ctx, db); err != nil {
		t.Fatal(err)
	}

	fresh, err := admindb.Open(filepath.Join(t.TempDir(), "b.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	if err := NewUserStore(dir).LoadIntoDB(ctx, fresh); err != nil {
		t.Fatal(err)
	}
	var name, perimeter, levels, permissions string
	if err := fresh.QueryRow(`SELECT name, perimeter, levels, permissions FROM team_accesses WHERE id='a1' AND team_id='t1'`).
		Scan(&name, &perimeter, &levels, &permissions); err != nil {
		t.Fatalf("accès non restauré : %v", err)
	}
	if name != "Exploitation" || perimeter != `{"domain":"*.corp.io","labels":{"env":"prod"}}` || levels != `{"proxies":"operate"}` || permissions != `["certs:deploy"]` {
		t.Fatalf("accès restauré : %s %s %s %s", name, perimeter, levels, permissions)
	}
}
