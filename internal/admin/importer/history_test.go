package importer

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestHistoryRoundTripEncryptedAndAdditive(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-historique")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO audit_log (actor, action, resource, detail) VALUES ('alice@x.fr','delete','proxy:app','motif-secret-audit')`)
	db.Exec(`INSERT INTO logs (ts, ip, path, message) VALUES ('2026-10-01 10:00:00','203.0.113.9','/login','ligne-de-journal')`)

	bk := &Backup{}
	if err := AttachHistory(db, bk); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bk)
	for _, leak := range []string{"alice@x.fr", "203.0.113.9", "ligne-de-journal", "motif-secret-audit"} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("%q lisible dans le snapshot", leak)
		}
	}
	sum, err := OpenHistorySummary(bk)
	if err != nil || sum.Tables["audit_log"] != 1 || sum.Tables["logs"] != 1 {
		t.Fatalf("résumé : %+v %v", sum, err)
	}

	db.Exec(`DELETE FROM audit_log`)
	db.Exec(`DELETE FROM logs`)
	res := Apply(db, bk, ImportSelection{ImportHistory: true, AllowPrivileged: true})
	if res.HistoryError != "" || res.HistoryRows != 2 {
		t.Fatalf("restauration : %+v", res)
	}
	// Restaurer deux fois n'ajoute rien (identifiants existants ignorés).
	if again := Apply(db, bk, ImportSelection{ImportHistory: true, AllowPrivileged: true}); again.HistoryRows != 0 {
		t.Fatalf("doublons : %d", again.HistoryRows)
	}
	if res := Apply(db, bk, ImportSelection{ImportHistory: true}); res.HistoryError == "" {
		t.Fatal("restauration autorisée hors superadmin")
	}
}

func TestHistoryRefusedWithoutKey(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "")
	db, _ := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	defer db.Close()
	bk := &Backup{}
	if err := AttachHistory(db, bk); err != ErrNoBackupKey || bk.History != "" {
		t.Fatalf("historique écrit sans clé : %v", err)
	}
}
