// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/importer"
)

func newTestScheduler(t *testing.T) *Scheduler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db, slog.New(slog.NewTextHandler(io.Discard, nil)))
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if cond() {
			return
		}
		time.Sleep(25 * time.Millisecond)
	}
	t.Fatalf("délai dépassé : %s", what)
}

func TestSnapshotStoresChecksumAndIsVerified(t *testing.T) {
	s := newTestScheduler(t)
	if err := s.TakeSnapshot("manuel", "", 0); err != nil {
		t.Fatal(err)
	}
	snaps := s.ListSnapshots()
	if len(snaps) != 1 || snaps[0].SHA256 == "" || snaps[0].VerifiedAt == nil {
		t.Fatalf("snapshot non vérifié : %+v", snaps)
	}
	// Altération : la vérification doit échouer et ne pas rafraîchir l'horodatage.
	s.db.Exec(`UPDATE backup_snapshots SET data = data || ' ' WHERE id=?`, snaps[0].ID)
	if err := s.VerifySnapshot(snaps[0].ID); err == nil || !strings.Contains(err.Error(), "somme de contrôle") {
		t.Fatalf("altération non détectée : %v", err)
	}
}

func TestDeliveryToDirDestinationWithRetention(t *testing.T) {
	s := newTestScheduler(t)
	dir := t.TempDir()
	d, err := s.SaveDestination(Destination{Name: "nas", Type: DestDir, Enabled: true, Config: map[string]string{"path": dir}, Retention: 2})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.TestDestination(context.Background(), d.ID); err != nil {
		t.Fatalf("test destination : %v", err)
	}
	for i := 0; i < 3; i++ {
		if err := s.TakeSnapshot("snap", "", 0); err != nil {
			t.Fatal(err)
		}
		n := i + 1
		waitFor(t, "envoi", func() bool {
			var c int
			s.db.QueryRow(`SELECT COUNT(*) FROM backup_deliveries WHERE ok=1`).Scan(&c)
			return c >= min(n, 2) && s.Status().Destinations[0].LastOKAt != nil
		})
		time.Sleep(1100 * time.Millisecond) // horodatages distincts (résolution à la seconde)
	}
	waitFor(t, "rétention", func() bool {
		entries, _ := os.ReadDir(dir)
		return len(entries) == 2
	})
	if st := s.Status(); st.Destinations[0].Copies != 2 || st.Destinations[0].LastError != "" {
		t.Fatalf("état : %+v", st.Destinations[0])
	}
}

func TestDeliveryFailureAlertsAndIsRecorded(t *testing.T) {
	s := newTestScheduler(t)
	var mu sync.Mutex
	var alerts []string
	s.SetNotifier(func(sev, title string, _ map[string]any) {
		mu.Lock()
		alerts = append(alerts, sev+":"+title)
		mu.Unlock()
	})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Error(w, "plein", http.StatusInsufficientStorage) }))
	defer srv.Close()
	if _, err := s.SaveDestination(Destination{Name: "dav", Type: DestWebDAV, Enabled: true, Config: map[string]string{"url": srv.URL}}); err != nil {
		t.Fatal(err)
	}
	if err := s.TakeSnapshot("snap", "", 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "alerte", func() bool { mu.Lock(); defer mu.Unlock(); return len(alerts) == 1 })
	st := s.Status().Destinations[0]
	if st.LastOKAt != nil || !strings.Contains(st.LastError, "507") {
		t.Fatalf("échec non enregistré : %+v", st)
	}
}

func TestWebDAVAndS3Drivers(t *testing.T) {
	store := map[string][]byte{}
	var mu sync.Mutex
	var sawAuth, sawSig string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		sawAuth = r.Header.Get("Authorization")
		switch r.Method {
		case http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			store[r.URL.Path] = b
			sawSig = r.Header.Get("x-amz-content-sha256")
			if strings.HasPrefix(r.URL.Path, "/remote.php") {
				w.WriteHeader(http.StatusCreated)
			}
		case http.MethodGet:
			b, ok := store[r.URL.Path]
			if !ok {
				http.NotFound(w, r)
				return
			}
			w.Write(b)
		case http.MethodDelete:
			delete(store, r.URL.Path)
			w.WriteHeader(http.StatusNoContent)
		}
	}))
	defer srv.Close()
	ctx := context.Background()

	dav, err := NewDriver(Destination{Type: DestWebDAV, Config: map[string]string{"url": srv.URL + "/remote.php/dav", "username": "u", "password": "p"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := dav.Put(ctx, "a.snap", []byte("x")); err != nil {
		t.Fatal(err)
	}
	if got, err := dav.Get(ctx, "a.snap"); err != nil || string(got) != "x" {
		t.Fatalf("webdav get : %q %v", got, err)
	}
	if !strings.HasPrefix(sawAuth, "Basic ") {
		t.Fatalf("auth webdav : %q", sawAuth)
	}

	s3, err := NewDriver(Destination{Type: DestS3, Config: map[string]string{
		"endpoint": srv.URL, "bucket": "bk", "prefix": "gpx", "access_key": "AK", "secret_key": "SK", "region": "eu-west-3"}})
	if err != nil {
		t.Fatal(err)
	}
	if err := s3.Put(ctx, "b.snap", []byte("yy")); err != nil {
		t.Fatal(err)
	}
	if _, ok := store["/bk/gpx/b.snap"]; !ok {
		t.Fatalf("chemin S3 inattendu : %v", store)
	}
	if !strings.HasPrefix(sawAuth, "AWS4-HMAC-SHA256 Credential=AK/") || !strings.Contains(sawAuth, "/eu-west-3/s3/aws4_request") ||
		sawSig != sha256Hex([]byte("yy")) {
		t.Fatalf("signature SigV4 : %q / %q", sawAuth, sawSig)
	}
	if err := s3.Delete(ctx, "b.snap"); err != nil {
		t.Fatal(err)
	}
	if err := s3.Delete(ctx, "absent.snap"); err != nil {
		t.Fatalf("suppression d'un objet absent : %v", err)
	}
}

func TestDriverRejectsTraversalAndBadConfig(t *testing.T) {
	d, _ := NewDriver(Destination{Type: DestDir, Config: map[string]string{"path": t.TempDir()}})
	for _, n := range []string{"../x", "a/b", "..", ""} {
		if err := d.Put(context.Background(), n, nil); err == nil {
			t.Fatalf("nom %q accepté", n)
		}
	}
	for _, c := range []Destination{
		{Type: DestDir, Config: map[string]string{"path": "relatif"}},
		{Type: DestWebDAV, Config: map[string]string{"url": "ftp://x"}},
		{Type: DestS3, Config: map[string]string{"endpoint": "http://x"}},
		{Type: "ftp"},
	} {
		if _, err := NewDriver(c); err == nil {
			t.Fatalf("configuration invalide acceptée : %+v", c)
		}
	}
}

func TestDestinationSecretsMaskedAndPreserved(t *testing.T) {
	s := newTestScheduler(t)
	d, err := s.SaveDestination(Destination{Name: "dav", Type: DestWebDAV, Enabled: true,
		Config: map[string]string{"url": "http://x.test", "username": "u", "password": "secret"}})
	if err != nil {
		t.Fatal(err)
	}
	if _, leaked := d.Config["password"]; leaked || d.Config["password_set"] != "true" {
		t.Fatalf("secret exposé : %+v", d.Config)
	}
	// Mise à jour sans ressaisir le mot de passe : conservé.
	if _, err := s.SaveDestination(Destination{ID: d.ID, Name: "dav", Type: DestWebDAV, Enabled: true,
		Config: map[string]string{"url": "http://y.test", "username": "u", "password_set": "true"}}); err != nil {
		t.Fatal(err)
	}
	got, _ := s.getDestination(d.ID)
	if got.Config["password"] != "secret" || got.Config["url"] != "http://y.test" {
		t.Fatalf("secret perdu : %+v", got.Config)
	}
}

func TestStaleScheduleDetected(t *testing.T) {
	s := newTestScheduler(t)
	sch := DefaultSchedule()
	sch.Enabled = true
	if err := s.SaveConfig(ScheduleConfig{Schedules: []Schedule{sch}}); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-72 * time.Hour).UTC().Format("2006-01-02 15:04:05")
	s.db.Exec(`INSERT INTO backup_snapshots (id, name, schedule_id, size, data, created_at) VALUES ('old','x',?,1,'{}',?)`, sch.ID, old)
	var alerts int
	s.SetNotifier(func(_, _ string, _ map[string]any) { alerts++ })
	s.checkStale()
	s.checkStale() // pas de doublon pour la même exécution manquée
	if alerts != 1 || len(s.Status().Stale) != 1 {
		t.Fatalf("alertes=%d état=%+v", alerts, s.Status().Stale)
	}
}

func TestRunningStateReportedDuringSnapshotAndDelivery(t *testing.T) {
	s := newTestScheduler(t)
	if s.Running() != nil || s.Status().Running != nil {
		t.Fatal("activité signalée alors que rien ne tourne")
	}

	// Une destination lente : la copie reste « en cours » après la fin du snapshot.
	release := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method == http.MethodPut {
			<-release
		}
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	defer func() {
		select {
		case <-release:
		default:
			close(release)
		}
	}()
	if _, err := s.SaveDestination(Destination{Name: "lente", Type: DestWebDAV, Enabled: true, Config: map[string]string{"url": srv.URL}}); err != nil {
		t.Fatal(err)
	}

	phases := map[string]bool{}
	done := make(chan struct{})
	go func() {
		defer close(done)
		for {
			if r := s.Running(); r != nil && r.Phase != "" {
				phases[r.Phase] = true
			}
			select {
			case <-time.After(time.Millisecond):
			case <-release:
				return
			}
		}
	}()
	if err := s.TakeSnapshot("suivi", "", 0); err != nil {
		t.Fatal(err)
	}
	waitFor(t, "copie en cours", func() bool {
		r := s.Running()
		return r != nil && len(r.Delivering) == 1 && r.Delivering[0] == "lente" && r.Name == ""
	})
	if st := s.Status(); st.Running == nil || len(st.Running.Delivering) != 1 {
		t.Fatalf("état : %+v", st.Running)
	}
	close(release)
	<-done
	waitFor(t, "fin de copie", func() bool { return s.Running() == nil })
	if !phases[PhaseExport] && !phases[PhaseSecrets] && !phases[PhaseVerify] {
		t.Logf("aucune phase intermédiaire observée (snapshot trop rapide) : %v", phases)
	}
}

func TestLastRunRecordsFailureAndSuccess(t *testing.T) {
	s := newTestScheduler(t)
	if s.LastRun() != nil {
		t.Fatal("résultat avant toute sauvegarde")
	}
	if err := s.TakeSnapshot("ok", "", 0); err != nil {
		t.Fatal(err)
	}
	if lr := s.LastRun(); lr == nil || !lr.OK || lr.Name != "ok" {
		t.Fatalf("succès : %+v", lr)
	}
	s.db.Exec(`DROP TABLE backup_snapshots`)
	if err := s.TakeSnapshot("ko", "", 0); err == nil {
		t.Fatal("échec attendu")
	}
	if lr := s.LastRun(); lr == nil || lr.OK || lr.Error == "" || s.Status().LastRun == nil {
		t.Fatalf("échec : %+v", lr)
	}
}

// La vérification d'un gros snapshot ne doit pas décoder son contenu : sur un snapshot de 100 Mo,
// l'ancienne version (décodage complet, section secrets déchiffrée deux fois) faisait tomber l'Admin.
func TestVerifyBigSnapshotStaysLight(t *testing.T) {
	resetKeys(t)
	s := newTestScheduler(t)
	ks := NewKeyStore(t.TempDir())
	key, _ := GenerateKey()
	if _, err := ks.Set(key); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	// La section secrets ne reprend pas les fichiers de plus de 8 Mo : plusieurs fichiers de 7 Mo.
	const files, each = 5, 7 << 20
	const payload = files * each
	for n := 0; n < files; n++ {
		big := make([]byte, each)
		for i := range big {
			big[i] = byte(i*7 + n)
		}
		if err := os.WriteFile(filepath.Join(dir, fmt.Sprintf("gros%d.bin", n)), big, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	s.SetSecretDirs(map[string]string{"state": dir})
	if err := s.TakeSnapshot("gros", "", 0); err != nil {
		t.Fatal(err)
	}
	var id string
	s.db.QueryRow(`SELECT id FROM backup_snapshots`).Scan(&id)

	// Pic de mémoire (et non cumul des allocations), échantillonné pendant l'opération.
	peak := func(fn func()) uint64 {
		runtime.GC()
		var base runtime.MemStats
		runtime.ReadMemStats(&base)
		var max uint64
		stop, done := make(chan struct{}), make(chan struct{})
		go func() {
			defer close(done)
			var m runtime.MemStats
			for {
				runtime.ReadMemStats(&m)
				if m.HeapAlloc > max {
					max = m.HeapAlloc
				}
				select {
				case <-stop:
					return
				case <-time.After(2 * time.Millisecond):
				}
			}
		}()
		fn()
		close(stop)
		<-done
		if max < base.HeapAlloc {
			return 0
		}
		return max - base.HeapAlloc
	}
	var snapSize int
	s.db.QueryRow(`SELECT size FROM backup_snapshots WHERE id=?`, id).Scan(&snapSize)

	newPeak := peak(func() {
		if err := s.VerifySnapshot(id); err != nil {
			t.Fatal(err)
		}
	})
	oldPeak := peak(func() { // ancienne méthode : décodage complet, sections déchiffrées
		var data string
		s.db.QueryRow(`SELECT data FROM backup_snapshots WHERE id=?`, id).Scan(&data)
		plain, _ := openSnapshot([]byte(data))
		bk, _, _ := importer.SummarizeBackup(plain)
		importer.OpenSecretsSummary(bk) //nolint:errcheck
	})
	t.Logf("snapshot de %d Mo : pic de %d Mo (nouvelle vérification) contre %d Mo (ancienne méthode)", snapSize>>20, newPeak>>20, oldPeak>>20)
	if limit := uint64(snapSize) * 3; newPeak > limit {
		t.Fatalf("vérification trop gourmande : pic de %d Mo pour un snapshot de %d Mo (limite %d Mo)", newPeak>>20, snapSize>>20, limit>>20)
	}
	if newPeak > oldPeak {
		t.Fatalf("la nouvelle vérification (%d Mo) n'est pas plus légère que l'ancienne (%d Mo)", newPeak>>20, oldPeak>>20)
	}
}

func TestInPlaceDecodeAndDecryptMatchRegularPath(t *testing.T) {
	resetKeys(t)
	ks := NewKeyStore(t.TempDir())
	key, _ := GenerateKey()
	if _, err := ks.Set(key); err != nil {
		t.Fatal(err)
	}
	plain := []byte(strings.Repeat(`{"version":"1","x":"données à chiffrer"}`, 1000))
	sealed, err := sealSnapshot(plain)
	if err != nil {
		t.Fatal(err)
	}
	want, err := openSnapshot(sealed)
	if err != nil || string(want) != string(plain) {
		t.Fatalf("chemin normal : %v", err)
	}
	got, err := openSnapshotConsume(append([]byte(nil), sealed...))
	if err != nil || string(got) != string(plain) {
		t.Fatalf("déchiffrement sur place : %v", err)
	}
	// Avec deux clés connues (rotation), le repli par essais successifs doit encore fonctionner.
	key2, _ := GenerateKey()
	if _, err := ks.Set(key2); err != nil {
		t.Fatal(err)
	}
	if got, err := openSnapshotConsume(append([]byte(nil), sealed...)); err != nil || string(got) != string(plain) {
		t.Fatalf("avec clé retirée : %v", err)
	}
	// Une altération doit être refusée, y compris sur place.
	bad := append([]byte(nil), sealed...)
	bad[len(bad)/2] ^= 0x01
	if _, err := openSnapshotConsume(bad); err == nil {
		t.Fatal("snapshot altéré accepté")
	}
}
