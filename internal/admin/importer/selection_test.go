package importer

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestSkipNodesKeepsTopologyUntouched(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	b := &Backup{DeclaredNodes: []map[string]any{{"id": "n1", "role": "edge", "name": "gw1"}}}

	Apply(db, b, ImportSelection{SkipNodes: true})
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM declared_nodes`).Scan(&n)
	if n != 0 {
		t.Fatalf("skip_nodes ignoré : %d nœud(s) recréé(s)", n)
	}
	Apply(db, b, ImportSelection{})
	db.QueryRow(`SELECT COUNT(*) FROM declared_nodes`).Scan(&n)
	if n != 1 {
		t.Fatalf("comportement par défaut modifié : %d", n)
	}
}

func TestPreviouslyMissingTablesRoundTrip(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO portal_groups (id, edge_name, name, members_json) VALUES ('g1','gw','Presta','["a@b.c"]')`)
	db.Exec(`INSERT INTO flows (id, name, trigger_kind, definition_json) VALUES ('p1','Réponse','manual','{}')`)
	db.Exec(`INSERT INTO flow_versions (flow_id, version, name, definition_json) VALUES ('p1',1,'Réponse','{}')`)
	tables := exportTables(db)
	for _, want := range []string{"portal_groups", "flows", "flow_versions"} {
		if len(tables[want]) != 1 {
			t.Fatalf("%s non exportée", want)
		}
	}
	db.Exec(`DELETE FROM portal_groups`)
	db.Exec(`DELETE FROM flows`)
	db.Exec(`DELETE FROM flow_versions`)
	w, _ := applyTables(db, tables, true, true)
	if w != 3 {
		t.Fatalf("lignes restaurées = %d", w)
	}
}
