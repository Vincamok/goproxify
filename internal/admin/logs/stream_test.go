package logs

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func streamCountLogs(t *testing.T, s *Store) int {
	t.Helper()
	var n int
	if err := s.db.QueryRow(`SELECT COUNT(*) FROM logs`).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n
}

func TestWriteStreamStoresLinesAndAdvancesTheCursorTogether(t *testing.T) {
	s, _ := newBatchStore(t)
	if c, err := s.StreamCursor("edge-a", "access"); err != nil || c != 0 {
		t.Fatalf("curseur initial = %d, %v", c, err)
	}
	if err := s.WriteStream("edge-a", "access", batchEntries(3), 42); err != nil {
		t.Fatal(err)
	}
	if n := streamCountLogs(t, s); n != 3 {
		t.Fatalf("%d lignes, attendu 3", n)
	}
	if c, _ := s.StreamCursor("edge-a", "access"); c != 42 {
		t.Fatalf("curseur = %d, attendu 42", c)
	}
	// Un autre flux ou une autre passerelle a sa propre position.
	for _, k := range [][2]string{{"edge-a", "system"}, {"edge-b", "access"}} {
		if c, _ := s.StreamCursor(k[0], k[1]); c != 0 {
			t.Errorf("curseur %v = %d, attendu 0", k, c)
		}
	}
}

func TestWriteStreamKeepsTheCursorAfterARestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.db")
	db, err := admindb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	s := New(db)
	if err := s.WriteStream("edge-a", "access", batchEntries(2), 17); err != nil {
		t.Fatal(err)
	}
	db.Close()

	db2, err := admindb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if c, err := New(db2).StreamCursor("edge-a", "access"); err != nil || c != 17 {
		t.Fatalf("après redémarrage : curseur = %d, %v ; attendu 17", c, err)
	}
}

func TestWriteStreamNeverMovesTheCursorBackwards(t *testing.T) {
	s, _ := newBatchStore(t)
	_ = s.WriteStream("edge-a", "access", batchEntries(1), 100)
	_ = s.WriteStream("edge-a", "access", batchEntries(1), 60)
	if c, _ := s.StreamCursor("edge-a", "access"); c != 100 {
		t.Fatalf("curseur = %d, attendu 100", c)
	}
	var persisted int64
	if err := s.db.QueryRow(`SELECT last_seq FROM edge_log_cursors WHERE node_id='edge-a' AND stream='access'`).Scan(&persisted); err != nil || persisted != 100 {
		t.Fatalf("curseur en base = %d, %v ; attendu 100", persisted, err)
	}
}

// Si une ligne du lot ne s'écrit pas, rien n'est gardé et le curseur ne bouge pas : la passerelle renverra le lot.
func TestWriteStreamIsAllOrNothing(t *testing.T) {
	s, _ := newBatchStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_on_boom BEFORE INSERT ON logs WHEN NEW.path = '/boom'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	entries := batchEntries(4)
	entries[2].Path = "/boom"
	if err := s.WriteStream("edge-a", "access", entries, 9); err == nil {
		t.Fatal("l'échec d'une ligne doit remonter")
	}
	if n := streamCountLogs(t, s); n != 0 {
		t.Fatalf("%d lignes gardées malgré l'échec, attendu 0", n)
	}
	if c, _ := s.StreamCursor("edge-a", "access"); c != 0 {
		t.Fatalf("curseur = %d après un échec, attendu 0", c)
	}
	var rows int
	_ = s.db.QueryRow(`SELECT COUNT(*) FROM edge_log_cursors`).Scan(&rows)
	if rows != 0 {
		t.Fatalf("%d curseurs en base après un échec", rows)
	}
}

func TestWriteStreamBroadcastsToLiveSubscribers(t *testing.T) {
	s, _ := newBatchStore(t)
	_, ch, cancel := s.Subscribe()
	defer cancel()
	if err := s.WriteStream("edge-a", "access", batchEntries(2), 5); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		select {
		case e := <-ch:
			if e.ID == 0 {
				t.Errorf("ligne diffusée sans identifiant : %+v", e)
			}
		default:
			t.Fatalf("seulement %d lignes diffusées sur 2", i)
		}
	}
}

func minuteRows(t *testing.T, s *Store, node string) map[string][4]int64 {
	t.Helper()
	rows, err := s.db.Query(`SELECT minute, domain, status, requests, bytes, latency_ms_sum, bots FROM logs_minute WHERE node_name = ?`, node)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string][4]int64{}
	for rows.Next() {
		var m, d string
		var st int
		var v [4]int64
		if err := rows.Scan(&m, &d, &st, &v[0], &v[1], &v[2], &v[3]); err != nil {
			t.Fatal(err)
		}
		out[m+"|"+d+"|"+itoa(st)] = v
	}
	return out
}

func itoa(n int) string { return fmt.Sprint(n) }

// Un cumul reçu remplace la valeur de sa minute : un renvoi ou une mise à jour ne s'y ajoute pas.
func TestWriteMinutesReplacesTheValueAndAdvancesTheCursor(t *testing.T) {
	s, _ := newBatchStore(t)
	row := MinuteRow{Minute: "2026-10-21T10:00", NodeName: "gw", Domain: "a.example.com", Status: 200, Requests: 5, Bytes: 500, LatencyMsSum: 50, Bots: 1}
	if err := s.WriteMinutes("edge-a", []MinuteRow{row}, 10); err != nil {
		t.Fatal(err)
	}
	// Même minute renvoyée (accusé perdu) : sans effet.
	if err := s.WriteMinutes("edge-a", []MinuteRow{row}, 10); err != nil {
		t.Fatal(err)
	}
	// La minute grossit : la nouvelle valeur remplace l'ancienne.
	row.Requests, row.Bytes = 8, 800
	if err := s.WriteMinutes("edge-a", []MinuteRow{row}, 12); err != nil {
		t.Fatal(err)
	}
	got := minuteRows(t, s, "gw")["2026-10-21T10:00|a.example.com|200"]
	if got != [4]int64{8, 800, 50, 1} {
		t.Fatalf("cumul = %v, attendu [8 800 50 1]", got)
	}
	if c, _ := s.StreamCursor("edge-a", "minute"); c != 12 {
		t.Fatalf("curseur = %d, attendu 12", c)
	}
}

func TestWriteMinutesIsAllOrNothing(t *testing.T) {
	s, _ := newBatchStore(t)
	if _, err := s.db.Exec(`CREATE TRIGGER fail_minute BEFORE INSERT ON logs_minute WHEN NEW.domain = 'boom'
		BEGIN SELECT RAISE(ABORT, 'boom'); END`); err != nil {
		t.Fatal(err)
	}
	rows := []MinuteRow{
		{Minute: "2026-10-21T10:00", NodeName: "gw", Domain: "ok", Status: 200, Requests: 1},
		{Minute: "2026-10-21T10:00", NodeName: "gw", Domain: "boom", Status: 200, Requests: 1},
	}
	if err := s.WriteMinutes("edge-a", rows, 7); err == nil {
		t.Fatal("l'échec doit remonter")
	}
	if got := minuteRows(t, s, "gw"); len(got) != 0 {
		t.Fatalf("%d cumuls gardés malgré l'échec", len(got))
	}
	if c, _ := s.StreamCursor("edge-a", "minute"); c != 0 {
		t.Fatalf("curseur = %d après un échec", c)
	}
}

// Une passerelle qui envoie ses cumuls n'est plus comptée deux fois : l'agrégation des lignes brutes l'ignore.
func TestTheRawAggregatorSkipsGatewaysThatSendTheirOwnTotals(t *testing.T) {
	s, _ := newBatchStore(t)
	ts := time.Date(2026, 10, 21, 10, 0, 5, 0, time.UTC)
	mk := func(node, nodeID string) Entry {
		return Entry{Ts: ts, Component: "edge", NodeName: node, NodeID: nodeID, Domain: "a.example.com", Method: "GET", Path: "/", Status: 200, IP: "198.51.100.1"}
	}
	s.WriteBatch([]Entry{mk("gw-old", "id-old"), mk("gw-old", "id-old"), mk("gw-new", "id-new"), mk("gw-new", "id-new"), mk("gw-new", "id-new")})
	if err := s.WriteMinutes("id-new", []MinuteRow{{Minute: "2026-10-21T10:00", NodeName: "gw-new", Domain: "a.example.com", Status: 200, Requests: 3}}, 1); err != nil {
		t.Fatal(err)
	}
	if err := AggregateNow(t.Context(), s.db); err != nil {
		t.Fatal(err)
	}
	if got := minuteRows(t, s, "gw-old")["2026-10-21T10:00|a.example.com|200"]; got[0] != 2 {
		t.Fatalf("gw-old : %v requêtes, attendu 2 (agrégé depuis les lignes brutes)", got[0])
	}
	if got := minuteRows(t, s, "gw-new")["2026-10-21T10:00|a.example.com|200"]; got[0] != 3 {
		t.Fatalf("gw-new : %v requêtes, attendu 3 (son propre cumul, pas 6)", got[0])
	}
}

func ipCounters(t *testing.T, s *Store) map[string]int64 {
	t.Helper()
	rows, err := s.db.Query(`SELECT node_id, minute, ip, errors FROM edge_ip_errors`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	out := map[string]int64{}
	for rows.Next() {
		var n, m, ip string
		var e int64
		if err := rows.Scan(&n, &m, &ip, &e); err != nil {
			t.Fatal(err)
		}
		out[n+"|"+m+"|"+ip] = e
	}
	return out
}

func TestWriteIPErrorsReplacesAndAdvancesTheCursor(t *testing.T) {
	s, _ := newBatchStore(t)
	row := IPErrorRow{Minute: "2026-10-21T10:00", IP: "203.0.113.9", Errors: 3}
	if err := s.WriteIPErrors("edge-a", []IPErrorRow{row}, 5); err != nil {
		t.Fatal(err)
	}
	row.Errors = 7
	if err := s.WriteIPErrors("edge-a", []IPErrorRow{row}, 8); err != nil {
		t.Fatal(err)
	}
	if got := ipCounters(t, s); len(got) != 1 || got["edge-a|2026-10-21T10:00|203.0.113.9"] != 7 {
		t.Fatalf("compteurs = %v, attendu une ligne à 7 (remplacée)", got)
	}
	if c, _ := s.StreamCursor("edge-a", "iperr"); c != 8 {
		t.Fatalf("curseur = %d", c)
	}
}

// Les compteurs portent une IP en clair : ils partent avec elle (RGPD) et au bout de 24 h.
func TestIPErrorCountersAreErasedWithTheIPAndPurgedAfterADay(t *testing.T) {
	s, _ := newBatchStore(t)
	now := time.Date(2026, 10, 21, 12, 0, 0, 0, time.UTC)
	_ = s.WriteIPErrors("edge-a", []IPErrorRow{
		{Minute: "2026-10-21T11:00", IP: "203.0.113.9", Errors: 3},
		{Minute: "2026-10-21T11:00", IP: "203.0.113.10", Errors: 4},
		{Minute: "2026-10-20T09:00", IP: "203.0.113.11", Errors: 5}, // plus de 24 h
	}, 3)

	s.PurgeIPErrors(now)
	if got := ipCounters(t, s); len(got) != 2 {
		t.Fatalf("après la purge : %v, attendu 2 compteurs", got)
	}
	res, err := s.EraseIP("203.0.113.9")
	if err != nil {
		t.Fatal(err)
	}
	if res.IPCounters != 1 {
		t.Fatalf("IPCounters = %d, attendu 1", res.IPCounters)
	}
	if got := ipCounters(t, s); len(got) != 1 {
		t.Fatalf("après l'effacement : %v", got)
	}
}
