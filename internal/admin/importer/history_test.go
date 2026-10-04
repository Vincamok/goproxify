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

func TestSecretsBundleOmitsTablesWithoutSecrets(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-prune")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	// Sans secret : déjà entière dans la section standard, inutile de la recopier dans la section secrets.
	db.Exec(`INSERT INTO ip_profiles (id, name, mode, cidrs) VALUES ('i1','Bureau','allow','["10.0.0.0/8"]')`)
	// Avec secret : la rédaction la modifie, elle doit rester dans la section secrets.
	db.Exec(`INSERT INTO auth_providers (id, name, provider, config) VALUES ('p1','oidc','oidc','{"client_secret":"s3cr3t"}')`)

	bk := &Backup{}
	if _, err := AttachSecrets(db, bk, nil, nil); err != nil {
		t.Fatal(err)
	}
	sb, err := openBundle(bk)
	if err != nil {
		t.Fatal(err)
	}
	if _, dup := sb.Tables["ip_profiles"]; dup {
		t.Fatal("table sans secret recopiée dans la section secrets")
	}
	if len(sb.Tables["auth_providers"]) != 1 {
		t.Fatalf("table avec secret absente de la section secrets : %v", keysOf(sb.Tables))
	}
	if len(exportTables(db)["ip_profiles"]) != 1 {
		t.Fatal("la section standard doit garder la table")
	}
}

func TestSizeNotesListsOnlyBigEntries(t *testing.T) {
	big := make([]byte, 3<<20)
	notes := SizeNotes("test", map[string][]map[string]any{"petite": {{"a": 1}}}, map[string][]byte{"petit": []byte("x"), "gros.bin": big})
	if len(notes) != 1 || !strings.Contains(notes[0], "gros.bin") || !strings.HasPrefix(notes[0], InfoPrefix) {
		t.Fatalf("notes : %v", notes)
	}
}

func keysOf(m map[string][]map[string]any) []string {
	var out []string
	for k := range m {
		out = append(out, k)
	}
	return out
}

// Cocher seulement « Secrets » restaure toujours les mêmes tables qu'avant l'allègement de la section :
// celles sans secret sont reprises de la section standard.
func TestSecretsRestoreStillRestoresTablesWithoutSecrets(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-compat")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO ip_profiles (id, name, mode, cidrs) VALUES ('i1','Bureau','allow','["10.0.0.0/8"]')`)
	db.Exec(`INSERT INTO auth_providers (id, name, provider, config) VALUES ('p1','oidc','oidc','{"client_secret":"s3cr3t"}')`)

	bk := &Backup{Tables: exportTables(db)}
	RedactSecrets(bk)
	if _, err := AttachSecrets(db, bk, nil, nil); err != nil {
		t.Fatal(err)
	}
	db.Exec(`DELETE FROM ip_profiles`)
	db.Exec(`DELETE FROM auth_providers`)

	res := Apply(db, bk, ImportSelection{ImportSecrets: true, AllowPrivileged: true}) // sans ImportConfig
	if res.SecretsError != "" {
		t.Fatalf("restauration : %+v", res)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM ip_profiles WHERE id='i1'`).Scan(&n)
	if n != 1 {
		t.Fatal("table sans secret non restaurée avec l'option Secrets")
	}
	var cfg string
	db.QueryRow(`SELECT config FROM auth_providers WHERE id='p1'`).Scan(&cfg)
	if !strings.Contains(cfg, "s3cr3t") {
		t.Fatalf("secret non restauré : %q", cfg)
	}
}
