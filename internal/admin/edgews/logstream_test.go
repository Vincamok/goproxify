package edgews

import (
	"database/sql"
	"fmt"
	"io"
	"log/slog"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func newIngestor(t *testing.T) (*LogStreamIngestor, *logs.Store) {
	g, store, _ := newIngestorDB(t)
	return g, store
}

func newIngestorDB(t *testing.T) (*LogStreamIngestor, *logs.Store, *sql.DB) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := logs.New(db)
	return &LogStreamIngestor{Store: store, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}, store, db
}

// streamBatch construit un lot contigu : les lignes after+1 … after+n.
func streamBatch(stream string, after int64, n int) edgeWS.LogStreamPayload {
	p := edgeWS.LogStreamPayload{Stream: stream, After: after}
	for i := int64(1); i <= int64(n); i++ {
		p.Entries = append(p.Entries, edgeWS.LogEntryPayload{
			Ts: "2026-10-21T10:00:00Z", Level: "info", Component: "edge", Domain: "app.example.com", Method: "GET",
			Path: fmt.Sprintf("/p/%d", after+i), Status: 200, IP: "198.51.100.1", Seq: after + i,
		})
	}
	return p
}

func countPaths(t *testing.T, store *logs.Store) []string {
	t.Helper()
	entries, _, err := store.Search(logs.SearchParams{PageSize: 100})
	if err != nil {
		t.Fatal(err)
	}
	var out []string
	for _, e := range entries {
		out = append(out, e.Path)
	}
	return out
}

func TestHandleStoresContiguousBatchesAndMovesTheCursor(t *testing.T) {
	g, store := newIngestor(t)
	if g.Handle("edge-a", "gw", streamBatch("access", 0, 3)) {
		t.Fatal("un premier lot contigu ne demande pas de reprise")
	}
	if g.Handle("edge-a", "gw", streamBatch("access", 3, 2)) {
		t.Fatal("un lot qui suit ne demande pas de reprise")
	}
	if c, _ := store.StreamCursor("edge-a", "access"); c != 5 {
		t.Fatalf("curseur = %d, attendu 5", c)
	}
	if got := countPaths(t, store); len(got) != 5 {
		t.Fatalf("%d lignes, attendu 5", len(got))
	}
	if cur := g.Cursors("edge-a"); cur["access"] != 5 || cur["system"] != 0 {
		t.Fatalf("Cursors = %v", cur)
	}
}

// Après une reconnexion la passerelle peut renvoyer des lignes déjà reçues : aucune n'est écrite deux fois.
func TestHandleDropsLinesAlreadyReceived(t *testing.T) {
	g, store := newIngestor(t)
	g.Handle("edge-a", "gw", streamBatch("access", 0, 4))
	// Renvoi complet depuis le début, puis renvoi qui chevauche (lignes 3 à 6).
	if g.Handle("edge-a", "gw", streamBatch("access", 0, 4)) {
		t.Fatal("un renvoi complet ne demande pas de reprise")
	}
	if g.Handle("edge-a", "gw", streamBatch("access", 2, 4)) {
		t.Fatal("un chevauchement ne demande pas de reprise")
	}
	if got := countPaths(t, store); len(got) != 6 {
		t.Fatalf("%d lignes, attendu 6 sans doublon : %v", len(got), got)
	}
	if c, _ := store.StreamCursor("edge-a", "access"); c != 6 {
		t.Fatalf("curseur = %d, attendu 6", c)
	}
}

// Un lot qui commence après la position de l'Admin saute des lignes : refusé, et la passerelle doit reprendre.
func TestHandleRefusesABatchThatSkipsLines(t *testing.T) {
	g, store := newIngestor(t)
	g.Handle("edge-a", "gw", streamBatch("access", 0, 2))
	if !g.Handle("edge-a", "gw", streamBatch("access", 5, 3)) {
		t.Fatal("un trou doit demander une reprise")
	}
	if got := countPaths(t, store); len(got) != 2 {
		t.Fatalf("le lot refusé a écrit des lignes : %d", len(got))
	}
	if c, _ := store.StreamCursor("edge-a", "access"); c != 2 {
		t.Fatalf("curseur = %d, attendu 2", c)
	}
}

func TestHandleKeepsEachNodeAndStreamApart(t *testing.T) {
	g, store := newIngestor(t)
	g.Handle("edge-a", "gw-a", streamBatch("access", 0, 3))
	g.Handle("edge-b", "gw-b", streamBatch("access", 0, 2))
	g.Handle("edge-a", "gw-a", streamBatch("system", 0, 1))
	for key, want := range map[[2]string]int64{{"edge-a", "access"}: 3, {"edge-b", "access"}: 2, {"edge-a", "system"}: 1, {"edge-b", "system"}: 0} {
		if c, _ := store.StreamCursor(key[0], key[1]); c != want {
			t.Errorf("curseur %v = %d, attendu %d", key, c, want)
		}
	}
	entries, _, _ := store.Search(logs.SearchParams{PageSize: 100})
	for _, e := range entries {
		if e.NodeID == "" || e.NodeName == "" {
			t.Fatalf("ligne sans identité de passerelle : %+v", e)
		}
	}
}

func TestHandleIgnoresAnUnknownStream(t *testing.T) {
	g, store := newIngestor(t)
	if g.Handle("edge-a", "gw", streamBatch("autre", 0, 2)) {
		t.Fatal("un flux inconnu ne demande pas de reprise")
	}
	if got := countPaths(t, store); len(got) != 0 {
		t.Fatalf("%d lignes écrites pour un flux inconnu", len(got))
	}
}

func TestHandleAsksForAResumeWhenTheWriteFails(t *testing.T) {
	g, store := newIngestor(t)
	if _, err := g.Store.StreamCursor("edge-a", "access"); err != nil { // charge le cache avant de casser la base
		t.Fatal(err)
	}
	_ = store
	db, err := admindb.Open(filepath.Join(t.TempDir(), "other.db"))
	if err != nil {
		t.Fatal(err)
	}
	broken := &LogStreamIngestor{Store: logs.New(db), Log: g.Log}
	db.Close() // toute écriture échoue désormais
	if !broken.Handle("edge-a", "gw", streamBatch("access", 0, 2)) {
		t.Fatal("une écriture en échec doit demander une reprise")
	}
}

func minuteBatch(after int64, rows ...edgeWS.MinuteRowPayload) edgeWS.MinuteStreamPayload {
	return edgeWS.MinuteStreamPayload{After: after, Rows: rows}
}

func mrow(minute string, requests, seq int64) edgeWS.MinuteRowPayload {
	return edgeWS.MinuteRowPayload{Minute: minute, NodeName: "gw", Domain: "a.example.com", Status: 200, Requests: requests, Bytes: requests * 10, Seq: seq}
}

func requestsOf(t *testing.T, db *sql.DB, minute string) int64 {
	t.Helper()
	var n int64
	err := db.QueryRow(`SELECT COALESCE(SUM(requests), 0) FROM logs_minute WHERE minute = ?`, minute).Scan(&n)
	if err != nil {
		t.Fatal(err)
	}
	return n
}

func TestHandleMinutesReplacesDeduplicatesAndRefusesGaps(t *testing.T) {
	g, _, db := newIngestorDB(t)
	if g.HandleMinutes("edge-a", "gw", minuteBatch(0, mrow("2026-10-21T10:00", 5, 100), mrow("2026-10-21T10:01", 2, 101))) {
		t.Fatal("un premier lot ne demande pas de reprise")
	}
	// La minute 10:01 grossit, et la 10:00 est renvoyée telle quelle : seule la nouvelle valeur compte.
	if g.HandleMinutes("edge-a", "gw", minuteBatch(100, mrow("2026-10-21T10:00", 5, 100), mrow("2026-10-21T10:01", 9, 102))) {
		t.Fatal("un lot qui chevauche ne demande pas de reprise")
	}
	if a, b := requestsOf(t, db, "2026-10-21T10:00"), requestsOf(t, db, "2026-10-21T10:01"); a != 5 || b != 9 {
		t.Fatalf("cumuls = %d et %d, attendu 5 et 9 (remplacés, pas additionnés)", a, b)
	}
	// Un lot qui saute des mises à jour est refusé.
	if !g.HandleMinutes("edge-a", "gw", minuteBatch(500, mrow("2026-10-21T10:02", 1, 501))) {
		t.Fatal("un trou doit demander une reprise")
	}
	if n := requestsOf(t, db, "2026-10-21T10:02"); n != 0 {
		t.Fatalf("le lot refusé a écrit %d requêtes", n)
	}
	if cur := g.Cursors("edge-a"); cur["minute"] != 102 {
		t.Fatalf("Cursors = %v, attendu minute=102", cur)
	}
}

func TestHandleIPErrorsReplacesDeduplicatesAndRefusesGaps(t *testing.T) {
	g, store, db := newIngestorDB(t)
	row := func(errors, seq int64) edgeWS.IPErrorRowPayload {
		return edgeWS.IPErrorRowPayload{Minute: "2026-10-21T10:00", IP: "203.0.113.9", Errors: errors, Seq: seq}
	}
	count := func() int64 {
		var n int64
		_ = db.QueryRow(`SELECT COALESCE(SUM(errors), 0) FROM edge_ip_errors`).Scan(&n)
		return n
	}
	if g.HandleIPErrors("edge-a", "gw", edgeWS.IPStreamPayload{After: 0, Rows: []edgeWS.IPErrorRowPayload{row(3, 10)}}) {
		t.Fatal("premier lot")
	}
	// Valeur à jour puis renvoi de l'ancienne : seule la plus récente compte.
	g.HandleIPErrors("edge-a", "gw", edgeWS.IPStreamPayload{After: 10, Rows: []edgeWS.IPErrorRowPayload{row(8, 11)}})
	g.HandleIPErrors("edge-a", "gw", edgeWS.IPStreamPayload{After: 0, Rows: []edgeWS.IPErrorRowPayload{row(3, 10)}})
	if n := count(); n != 8 {
		t.Fatalf("%d erreurs, attendu 8", n)
	}
	if !g.HandleIPErrors("edge-a", "gw", edgeWS.IPStreamPayload{After: 99, Rows: []edgeWS.IPErrorRowPayload{row(1, 100)}}) {
		t.Fatal("un trou doit demander une reprise")
	}
	if c, _ := store.StreamCursor("edge-a", "iperr"); c != 11 {
		t.Fatalf("curseur = %d, attendu 11", c)
	}
}
