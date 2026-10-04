package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/importer"
)

func resetKeys(t *testing.T) {
	t.Setenv("GPX_BACKUP_KEY", "")
	importer.SetKeyRing("", nil)
	t.Cleanup(func() { importer.SetKeyRing("", nil) })
}

func TestKeyStoreLifecycleAndEnvPriority(t *testing.T) {
	resetKeys(t)
	dir := t.TempDir()
	ks := NewKeyStore(dir)
	if st := ks.Status(); st.Source != "none" || !st.CanChange {
		t.Fatalf("état initial : %+v", st)
	}
	if _, err := ks.Set("court"); err == nil {
		t.Fatal("clé trop courte acceptée")
	}
	key, err := GenerateKey()
	if err != nil || len(key) < 40 {
		t.Fatalf("génération : %q %v", key, err)
	}
	if rotated, err := ks.Set(key); err != nil || rotated {
		t.Fatalf("première clé : rotated=%v err=%v", rotated, err)
	}
	if _, ok := importer.BackupKey(); !ok {
		t.Fatal("clé du fichier non utilisée par le chiffrement")
	}
	if st := ks.Status(); st.Source != "file" || st.Fingerprint != Fingerprint(key) {
		t.Fatalf("état : %+v", st)
	}
	if info, err := os.Stat(filepath.Join(dir, "backup-keys.json")); err != nil || (os.PathSeparator == '/' && info.Mode().Perm()&0o077 != 0) {
		t.Fatalf("fichier clé : %v %v", info, err)
	}
	importer.SetKeyRing("", nil) // redémarrage
	NewKeyStore(dir)
	if importer.KeySource() != "file" {
		t.Fatal("clé non rechargée depuis le fichier")
	}
	if got, err := ks.Reveal(""); err != nil || got != key {
		t.Fatalf("révélation : %q %v", got, err)
	}

	// La variable d'environnement l'emporte et verrouille l'interface (sauf les clés retirées).
	t.Setenv("GPX_BACKUP_KEY", "cle-depuis-lenvironnement")
	if st := ks.Status(); st.Source != "env" || st.CanChange {
		t.Fatalf("priorité env : %+v", st)
	}
	if _, err := ks.Set(key); err != ErrKeyFromEnv {
		t.Fatalf("changement autorisé malgré la variable d'environnement : %v", err)
	}
	if err := ks.Deactivate(); err != ErrKeyFromEnv {
		t.Fatalf("désactivation autorisée : %v", err)
	}
	if _, err := ks.Reveal(""); err != ErrKeyFromEnv {
		t.Fatalf("révélation de la clé d'environnement : %v", err)
	}
}

func TestRotationKeepsOldSnapshotsReadable(t *testing.T) {
	resetKeys(t)
	s := newTestScheduler(t)
	ks := NewKeyStore(t.TempDir())
	keyA, _ := GenerateKey()
	keyB, _ := GenerateKey()

	if _, err := ks.Set(keyA); err != nil {
		t.Fatal(err)
	}
	if err := s.TakeSnapshot("avec-A", "", 0); err != nil {
		t.Fatal(err)
	}
	var idA, data string
	s.db.QueryRow(`SELECT id, data FROM backup_snapshots`).Scan(&idA, &data)
	if !strings.HasPrefix(data, backupEncPrefix) {
		t.Fatal("snapshot non chiffré avec la clé de l'interface")
	}

	rotated, err := ks.Set(keyB)
	if err != nil || !rotated {
		t.Fatalf("rotation : %v %v", rotated, err)
	}
	if st := ks.Status(); st.Fingerprint != Fingerprint(keyB) || len(st.Retired) != 1 || st.Retired[0].Fingerprint != Fingerprint(keyA) {
		t.Fatalf("trousseau : %+v", st)
	}
	if err := s.VerifySnapshot(idA); err != nil {
		t.Fatalf("ancien snapshot illisible après rotation : %v", err)
	}
	if err := s.TakeSnapshot("avec-B", "", 0); err != nil {
		t.Fatal(err)
	}

	// Oublier l'ancienne clé : le snapshot qu'elle avait chiffré n'est plus lisible, l'autre l'est.
	if err := ks.ForgetRetired(Fingerprint(keyA)); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifySnapshot(idA); err == nil {
		t.Fatal("snapshot lisible sans sa clé")
	}
	// La rajouter à la main (cas d'un changement de GPX_BACKUP_KEY) le rend de nouveau lisible.
	if err := ks.AddRetired(keyA); err != nil {
		t.Fatal(err)
	}
	if err := s.VerifySnapshot(idA); err != nil {
		t.Fatalf("snapshot toujours illisible après ajout de l'ancienne clé : %v", err)
	}
	if got, err := ks.Reveal(Fingerprint(keyA)); err != nil || got != keyA {
		t.Fatalf("révélation d'une clé retirée : %q %v", got, err)
	}

	// Désactiver conserve la clé parmi les retirées.
	if err := ks.Deactivate(); err != nil {
		t.Fatal(err)
	}
	if st := ks.Status(); st.Source != "none" || len(st.Retired) != 2 {
		t.Fatalf("après désactivation : %+v", st)
	}
}

func TestLegacySingleKeyFileIsMigrated(t *testing.T) {
	resetKeys(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "backup.key"), []byte("ancienne-cle-unique-123"), 0o600)
	ks := NewKeyStore(dir)
	if st := ks.Status(); st.Source != "file" || st.Fingerprint != Fingerprint("ancienne-cle-unique-123") {
		t.Fatalf("migration : %+v", st)
	}
}
