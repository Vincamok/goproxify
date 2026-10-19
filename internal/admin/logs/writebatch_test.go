package logs

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func newBatchStore(t *testing.T) (*Store, string) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "admin.db")
	db, err := admindb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return New(db), path
}

func batchEntries(n int) []Entry {
	out := make([]Entry, n)
	base := time.Now()
	for i := range out {
		out[i] = Entry{
			Ts: base.Add(time.Duration(i) * time.Millisecond), Component: "edge", NodeName: "edge-a",
			Domain: fmt.Sprintf("d%d.example.fr", i%7), Method: "GET", Path: fmt.Sprintf("/p/%d", i),
			Status: 200, IP: fmt.Sprintf("198.51.100.%d", i%250), LatencyMs: 3, Bytes: int64(100 + i),
			RequestID: fmt.Sprintf("req-%d", i),
		}
	}
	return out
}

func TestWriteBatchSpansSeveralTransactions(t *testing.T) {
	s, _ := newBatchStore(t)
	const n = writeBatchSize*2 + 37
	s.WriteBatch(batchEntries(n))

	var count int
	var maxID, minID int64
	if err := s.db.QueryRow(`SELECT COUNT(*), MAX(id), MIN(id) FROM logs WHERE retained_until IS NOT NULL`).Scan(&count, &maxID, &minID); err != nil {
		t.Fatal(err)
	}
	if count != n {
		t.Fatalf("%d lignes écrites, attendu %d", count, n)
	}
	if maxID-minID != int64(n-1) {
		t.Fatalf("ids non consécutifs : %d à %d", minID, maxID)
	}
}

// Les abonnés SSE ne voient une entrée qu'une fois écrite, avec son id (le canal garde 128 entrées).
func TestWriteBatchBroadcastsAfterCommit(t *testing.T) {
	s, _ := newBatchStore(t)
	_, ch, cancel := s.Subscribe()
	defer cancel()

	const n = 100
	s.WriteBatch(batchEntries(n))

	for i := 0; i < n; i++ {
		select {
		case e := <-ch:
			if e.ID == 0 {
				t.Fatal("entrée diffusée sans id")
			}
			var present int
			s.db.QueryRow(`SELECT COUNT(*) FROM logs WHERE id=?`, e.ID).Scan(&present)
			if present != 1 {
				t.Fatalf("entrée %d diffusée mais absente de la base", e.ID)
			}
		case <-time.After(3 * time.Second):
			t.Fatalf("%d entrées diffusées sur %d", i, n)
		}
	}
}

func TestWriteBatchEmptyIsHarmless(t *testing.T) {
	s, _ := newBatchStore(t)
	s.WriteBatch(nil)
	s.WriteBatch([]Entry{})
}

// Mesure : sans point de contrôle automatique, la taille du WAL est l'écriture cumulée des commits.
func TestWriteBatchWritesLessThanOneTransactionPerEntry(t *testing.T) {
	walAfter := func(batch bool) int64 {
		s, path := newBatchStore(t)
		if _, err := s.db.Exec(`PRAGMA wal_autocheckpoint = 0`); err != nil {
			t.Fatal(err)
		}
		entries := batchEntries(1500)
		if batch {
			// Lots de la taille que les passerelles expédient.
			for i := 0; i < len(entries); i += 50 {
				s.WriteBatch(entries[i:min(i+50, len(entries))])
			}
		} else {
			for _, e := range entries {
				s.Write(e)
			}
		}
		fi, err := os.Stat(path + "-wal")
		if err != nil {
			t.Fatal(err)
		}
		return fi.Size()
	}
	single, batched := walAfter(false), walAfter(true)
	t.Logf("WAL pour 1500 lignes : %d Ko une par une, %d Ko par lots de 50 (%.1fx)", single/1024, batched/1024, float64(single)/float64(batched))
	if batched*2 > single {
		t.Fatalf("lots de 50 : %d octets de WAL contre %d une par une, attendu au moins deux fois moins", batched, single)
	}
}
