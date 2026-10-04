package edge

import (
	"database/sql"
	"path/filepath"
	"testing"
)

// Reproduit la production : base WAL gardée ouverte (et écrite) par la passerelle pendant l'export.
func TestVacuumCopyOfLiveWALDatabase(t *testing.T) {
	path := filepath.Join(t.TempDir(), "bans.db")
	live, err := sql.Open("sqlite", path+"?_pragma=journal_mode(WAL)&_pragma=synchronous(NORMAL)")
	if err != nil {
		t.Fatal(err)
	}
	defer live.Close()
	live.SetMaxOpenConns(1)
	live.Exec(`CREATE TABLE b (ip TEXT)`)
	live.Exec(`INSERT INTO b VALUES ('203.0.113.9')`)

	data, err := vacuumCopy(path)
	if err != nil {
		t.Fatalf("copie d'une base WAL ouverte : %v", err)
	}
	if len(data) == 0 {
		t.Fatal("copie vide")
	}
}
