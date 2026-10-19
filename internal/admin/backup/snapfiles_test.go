package backup

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func snapFiles(t *testing.T, dir string) []string {
	t.Helper()
	entries, _ := os.ReadDir(dir)
	var out []string
	for _, e := range entries {
		if strings.HasSuffix(e.Name(), ".snap") {
			out = append(out, e.Name())
		}
	}
	return out
}

func dataLen(t *testing.T, s *Scheduler, id string) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT length(data) FROM backup_snapshots WHERE id=?`, id).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

// Avec snapDir, le fichier est la copie de référence : la base ne garde que les métadonnées, et la
// relecture, la vérification et la suppression passent par le fichier.
func TestSnapshotLivesInItsFileNotInTheDatabase(t *testing.T) {
	s := newTestScheduler(t)
	dir := filepath.Join(t.TempDir(), "backups")
	s.SetSnapDir(dir)

	if err := s.TakeSnapshot("manuel", "", 0); err != nil {
		t.Fatal(err)
	}
	snaps := s.ListSnapshots()
	if len(snaps) != 1 || snaps[0].SizeBytes == 0 || snaps[0].VerifiedAt == nil {
		t.Fatalf("snapshot : %+v", snaps)
	}
	id := snaps[0].ID
	if n := dataLen(t, s, id); n != 0 {
		t.Fatalf("%d octets gardés en base, attendu 0", n)
	}
	if files := snapFiles(t, dir); len(files) != 1 {
		t.Fatalf("fichiers : %v", files)
	}
	if plain, _, err := s.GetSnapshotData(id); err != nil || len(plain) == 0 {
		t.Fatalf("relecture depuis le fichier : %v", err)
	}
	if err := s.VerifySnapshot(id); err != nil {
		t.Fatalf("vérification depuis le fichier : %v", err)
	}

	// Un fichier altéré est détecté, et sa disparition aussi.
	path := s.snapFilePath(id)
	raw, _ := os.ReadFile(path)
	os.WriteFile(path, append(raw, ' '), 0o600)
	if err := s.VerifySnapshot(id); err == nil || !strings.Contains(err.Error(), "somme de contrôle") {
		t.Fatalf("fichier altéré non détecté : %v", err)
	}
	if err := s.DeleteSnapshot(id); err != nil {
		t.Fatal(err)
	}
	if files := snapFiles(t, dir); len(files) != 0 {
		t.Fatalf("fichier resté après suppression : %v", files)
	}
}

// Sans répertoire de snapshots, le contenu reste en base : aucune sauvegarde ne se perd.
func TestSnapshotStaysInDatabaseWithoutSnapDir(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.TakeSnapshot("manuel", "", 0); err != nil {
		t.Fatal(err)
	}
	snaps := s.ListSnapshots()
	if len(snaps) != 1 || dataLen(t, s, snaps[0].ID) == 0 {
		t.Fatalf("contenu absent de la base sans snapDir : %+v", snaps)
	}
	if _, _, err := s.GetSnapshotData(snaps[0].ID); err != nil {
		t.Fatal(err)
	}
}

// La rétention d'une planification supprimait les lignes mais jamais les fichiers : backups/ grossissait.
func TestRetentionRemovesPrunedSnapshotFiles(t *testing.T) {
	s := newTestScheduler(t)
	dir := filepath.Join(t.TempDir(), "backups")
	s.SetSnapDir(dir)
	for i := 0; i < 4; i++ {
		if err := s.TakeSnapshot("planif", "sch-1", 2); err != nil {
			t.Fatal(err)
		}
	}
	if n := len(s.ListSnapshots()); n != 2 {
		t.Fatalf("%d snapshots gardés, attendu 2", n)
	}
	if files := snapFiles(t, dir); len(files) != 2 {
		t.Fatalf("%d fichiers gardés, attendu 2 : %v", len(files), files)
	}
}

func TestMigrateSnapshotsToFilesFreesTheDatabaseCopy(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.TakeSnapshot("ancien", "", 0); err != nil { // sans snapDir : contenu en base
		t.Fatal(err)
	}
	id := s.ListSnapshots()[0].ID
	if dataLen(t, s, id) == 0 {
		t.Fatal("contenu absent de la base")
	}
	before, _, _ := s.GetSnapshotData(id)

	dir := filepath.Join(t.TempDir(), "backups")
	s.SetSnapDir(dir)
	if n := s.MigrateSnapshotsToFiles(); n != 1 {
		t.Fatalf("%d snapshots libérés, attendu 1", n)
	}
	if dataLen(t, s, id) != 0 {
		t.Fatal("copie en base non libérée")
	}
	if files := snapFiles(t, dir); len(files) != 1 {
		t.Fatalf("fichiers : %v", files)
	}
	after, _, err := s.GetSnapshotData(id)
	if err != nil || string(after) != string(before) {
		t.Fatalf("contenu changé par la migration : %v", err)
	}
	if err := s.VerifySnapshot(id); err != nil {
		t.Fatal(err)
	}
	if n := s.MigrateSnapshotsToFiles(); n != 0 {
		t.Fatalf("seconde passe : %d, attendu 0 (idempotent)", n)
	}
}

// Un fichier qui ne correspond pas à la copie en base n'autorise pas à la supprimer.
func TestMigrateKeepsTheDatabaseCopyWhenTheFileDiffers(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.TakeSnapshot("ancien", "", 0); err != nil {
		t.Fatal(err)
	}
	id := s.ListSnapshots()[0].ID
	dir := filepath.Join(t.TempDir(), "backups")
	os.MkdirAll(dir, 0o700)
	os.WriteFile(filepath.Join(dir, "20260101T000000Z_ancien_"+id+".snap"), []byte("autre contenu"), 0o600)
	s.SetSnapDir(dir)

	if n := s.MigrateSnapshotsToFiles(); n != 0 {
		t.Fatalf("%d libérés malgré un fichier différent", n)
	}
	if dataLen(t, s, id) == 0 {
		t.Fatal("copie en base supprimée alors que le fichier diffère")
	}
}
