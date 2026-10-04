package importer

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestSecretsRoundTrip(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "cle-de-test")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1','a@b.c','HASH-U1','superadmin')`)
	db.Exec(`INSERT INTO auth_providers (id, name, provider, config) VALUES ('p1','oidc','oidc','{"client_secret":"s3cr3t"}')`)

	state := t.TempDir()
	cfgDir := t.TempDir()
	os.WriteFile(filepath.Join(state, "architecture.json"), []byte(`{"nodes":[]}`), 0o600)

	bk := &Backup{Tables: exportTables(db)}
	RedactSecrets(bk)
	if _, err := AttachSecrets(db, bk, map[string]string{"state": state}, map[string][]byte{"admin-ha.json": []byte(`{"node_id":"a1"}`)}); err != nil {
		t.Fatal(err)
	}
	raw, _ := json.Marshal(bk)
	for _, leak := range []string{"HASH-U1", "s3cr3t", `{\"nodes\"`} {
		if strings.Contains(string(raw), leak) {
			t.Fatalf("%q lisible dans le snapshot", leak)
		}
	}

	db.Exec(`DELETE FROM users`)
	db.Exec(`DELETE FROM auth_providers`)
	os.Remove(filepath.Join(state, "architecture.json"))

	res := Apply(db, bk, ImportSelection{ImportSecrets: true, AllowPrivileged: true, SecretDirs: map[string]string{"state": state, "config": cfgDir}})
	if res.SecretsError != "" || res.SecretFiles != 2 {
		t.Fatalf("restauration: %+v", res)
	}
	var hash, cfg string
	db.QueryRow(`SELECT password_hash FROM users WHERE id='u1'`).Scan(&hash)
	db.QueryRow(`SELECT config FROM auth_providers WHERE id='p1'`).Scan(&cfg)
	if hash != "HASH-U1" || !strings.Contains(cfg, "s3cr3t") {
		t.Fatalf("secrets non restaurés: %q %q", hash, cfg)
	}
	if b, _ := os.ReadFile(filepath.Join(cfgDir, "admin-ha.json")); string(b) != `{"node_id":"a1"}` {
		t.Fatalf("config HA non restaurée dans le dossier dédié : %q", b)
	}
	if b, _ := os.ReadFile(filepath.Join(state, "architecture.json")); string(b) != `{"nodes":[]}` {
		t.Fatalf("fichier non restauré: %q", b)
	}
}

func TestSecretsRequireKeyAndSuperadmin(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	t.Setenv("GPX_BACKUP_KEY", "")
	bk := &Backup{}
	if _, err := AttachSecrets(db, bk, nil, nil); !errors.Is(err, ErrNoBackupKey) || bk.Secrets != "" {
		t.Fatalf("section écrite sans clé: %v", err)
	}

	t.Setenv("GPX_BACKUP_KEY", "k1")
	if _, err := AttachSecrets(db, bk, nil, nil); err != nil {
		t.Fatal(err)
	}
	if res := Apply(db, bk, ImportSelection{ImportSecrets: true}); res.SecretsError == "" {
		t.Fatal("restauration autorisée sans superadmin")
	}
	t.Setenv("GPX_BACKUP_KEY", "k2")
	if res := Apply(db, bk, ImportSelection{ImportSecrets: true, AllowPrivileged: true}); res.SecretsError == "" {
		t.Fatal("restauration avec une mauvaise clé")
	}
}

func TestSecretsRestoreRejectsPathTraversal(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "k")
	db, _ := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	defer db.Close()
	plain, _ := json.Marshal(SecretBundle{Files: map[string][]byte{"state/../evil.txt": []byte("x")}})
	sealed, _ := sealSecrets(plain)
	root := t.TempDir()
	state := filepath.Join(root, "state")
	os.MkdirAll(state, 0o700)
	if _, files, _, err := restoreSecrets(db, &Backup{Secrets: sealed}, map[string]string{"state": state}); err != nil || files != 0 {
		t.Fatalf("files=%d err=%v", files, err)
	}
	if _, err := os.Stat(filepath.Join(root, "evil.txt")); err == nil {
		t.Fatal("écriture hors du dossier cible")
	}
}
