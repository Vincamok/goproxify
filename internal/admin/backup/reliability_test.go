// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
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
