// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package importer

import (
	"database/sql"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func privilegedDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "i.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('sa','sa@t','x','superadmin'), ('a','a@t','x','admin'), ('dpo','dpo@t','x','dpo')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique'), ('ops','Ops')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func roleOf(db *sql.DB, email string) string {
	var r string
	db.QueryRow(`SELECT role FROM users WHERE email=?`, email).Scan(&r) //nolint:errcheck
	return r
}

func isMember(db *sql.DB, team, user string) bool {
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM team_members WHERE team_id=? AND user_id=?`, team, user).Scan(&n) //nolint:errcheck
	return n == 1
}

// Une sauvegarde importée par un admin écrasait le rôle des comptes existants : il pouvait se
// passer superadmin ou dpo, rétrograder le superadmin, ou entrer dans une équipe portant gdpr:reveal.
func TestImportCannotGrantPrivileges(t *testing.T) {
	b := &Backup{
		Users: []BackupUser{
			{Email: "a@t", Role: "superadmin"},
			{Email: "sa@t", Role: "user"},
			{Email: "dpo@t", Role: "user"},
			{Email: "new@t", Role: "dpo"},
		},
		Tables: map[string][]map[string]any{
			"team_members": {{"team_id": "legal", "user_id": "a"}, {"team_id": "ops", "user_id": "a"}},
		},
	}
	db := privilegedDB(t)
	Apply(db, b, ImportSelection{ImportUsers: true, ImportConfig: true, OnConflict: "overwrite"})
	for email, want := range map[string]string{"a@t": "admin", "sa@t": "superadmin", "dpo@t": "dpo", "new@t": "user"} {
		if got := roleOf(db, email); got != want {
			t.Errorf("import par un admin : %s a le rôle %q, attendu %q", email, got, want)
		}
	}
	if isMember(db, "legal", "a") || !isMember(db, "ops", "a") {
		t.Errorf("import par un admin : legal=%v (attendu false) ops=%v (attendu true)", isMember(db, "legal", "a"), isMember(db, "ops", "a"))
	}

	// Le superadmin peut restaurer rôle dpo et équipe RGPD, jamais un second superadmin.
	db = privilegedDB(t)
	b.Users = []BackupUser{{Email: "a@t", Role: "dpo"}, {Email: "dpo@t", Role: "user"}, {Email: "new@t", Role: "superadmin"}}
	Apply(db, b, ImportSelection{ImportUsers: true, ImportConfig: true, OnConflict: "overwrite", AllowPrivileged: true})
	for email, want := range map[string]string{"a@t": "dpo", "dpo@t": "user", "new@t": "user", "sa@t": "superadmin"} {
		if got := roleOf(db, email); got != want {
			t.Errorf("import par le superadmin : %s a le rôle %q, attendu %q", email, got, want)
		}
	}
	if !isMember(db, "legal", "a") {
		t.Error("import par le superadmin : membre de l'équipe RGPD non restauré")
	}
}
