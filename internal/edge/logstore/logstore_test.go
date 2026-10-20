// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/ipcrypt"
)

func openTest(t *testing.T, mutate ...func(*Options)) *Store {
	t.Helper()
	opts := Options{Dir: filepath.Join(t.TempDir(), "logs")}
	for _, m := range mutate {
		m(&opts)
	}
	s, err := Open(opts)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return s
}

func key(t *testing.T) []byte {
	t.Helper()
	k, err := ipcrypt.NewKey()
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func at(s string) time.Time {
	ts, err := time.Parse(time.RFC3339, s)
	if err != nil {
		panic(err)
	}
	return ts
}

func access(ts time.Time, ip string) Entry {
	return Entry{
		Ts: ts, Level: "info", Component: "edge", Domain: "app.example.com", Method: "GET", Path: "/api/ping",
		Status: 200, Bytes: 1024, LatencyMs: 12, IP: ip, UserAgent: "curl/8", Referrer: "https://ref.example/",
		RequestID: "req-1", WAFMatches: []string{"sqli", "xss"}, ThreatSignal: "scan", TLSJA3: "abc", TLSJA4: "t13d",
	}
}

func TestRoundTripKeepsEveryField(t *testing.T) {
	s := openTest(t)
	in := access(at("2026-10-21T10:00:00.123456Z"), "203.0.113.42")
	if !s.Add(KindAccess, in) {
		t.Fatal("Add refusé")
	}
	s.Flush()

	rows, err := s.ReadAfter(KindAccess, 0, 10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("ReadAfter = %d lignes, %v", len(rows), err)
	}
	got := rows[0].Entry
	if !got.Ts.Equal(in.Ts) || got.Domain != in.Domain || got.Path != in.Path || got.Status != in.Status ||
		got.Bytes != in.Bytes || got.LatencyMs != in.LatencyMs || got.IP != in.IP || got.UserAgent != in.UserAgent ||
		got.Referrer != in.Referrer || got.RequestID != in.RequestID || got.ThreatSignal != in.ThreatSignal ||
		got.TLSJA3 != in.TLSJA3 || got.TLSJA4 != in.TLSJA4 || strings.Join(got.WAFMatches, ",") != "sqli,xss" {
		t.Fatalf("ligne relue différente :\n got %+v\nwant %+v", got, in)
	}
	if rows[0].Pseudonymized {
		t.Error("ligne en clair marquée pseudonymisée")
	}
}

func TestIDsGrowAcrossPeriodsAndTheCursorResumes(t *testing.T) {
	s := openTest(t)
	// Deux semaines différentes (lundis 2026-10-12 et 2026-10-19), puis une troisième.
	for i, ts := range []string{"2026-10-13T08:00:00Z", "2026-10-14T08:00:00Z", "2026-10-20T08:00:00Z", "2026-10-27T08:00:00Z"} {
		e := access(at(ts), "198.51.100.1")
		e.RequestID = string(rune('a' + i))
		s.Add(KindAccess, e)
	}
	s.Flush()

	for _, name := range []string{"access-2026-10-12.db", "access-2026-10-19.db", "access-2026-10-26.db"} {
		if _, err := os.Stat(filepath.Join(s.opts.Dir, name)); err != nil {
			t.Errorf("fichier de période absent : %v", err)
		}
	}
	all, err := s.ReadAfter(KindAccess, 0, 100)
	if err != nil || len(all) != 4 {
		t.Fatalf("lecture complète = %d lignes, %v", len(all), err)
	}
	for i := 1; i < len(all); i++ {
		if all[i].ID <= all[i-1].ID {
			t.Fatalf("identifiants non croissants : %d puis %d", all[i-1].ID, all[i].ID)
		}
	}
	// Reprendre au milieu : le curseur est l'identifiant de la dernière ligne vue, d'un fichier à l'autre.
	rest, err := s.ReadAfter(KindAccess, all[1].ID, 100)
	if err != nil || len(rest) != 2 || rest[0].ID != all[2].ID {
		t.Fatalf("reprise après %d = %d lignes (%v), premier %d, attendu %d", all[1].ID, len(rest), err, firstID(rest), all[2].ID)
	}
	page, _ := s.ReadAfter(KindAccess, 0, 3)
	if len(page) != 3 || page[2].ID != all[2].ID {
		t.Fatalf("limite de 3 lignes non respectée : %d lignes", len(page))
	}
}

func firstID(rows []Row) int64 {
	if len(rows) == 0 {
		return 0
	}
	return rows[0].ID
}

func TestSystemLogsAreMonthlyAndSeparate(t *testing.T) {
	s := openTest(t)
	s.Add(KindSystem, Entry{Ts: at("2026-10-31T23:59:00Z"), Level: "warn", Component: "edge", Message: "fin octobre"})
	s.Add(KindSystem, Entry{Ts: at("2026-11-01T00:01:00Z"), Level: "info", Component: "edge", Message: "début novembre"})
	s.Add(KindAccess, access(at("2026-10-31T23:59:00Z"), "198.51.100.1"))
	s.Flush()

	for _, name := range []string{"system-2026-10.db", "system-2026-11.db"} {
		if _, err := os.Stat(filepath.Join(s.opts.Dir, name)); err != nil {
			t.Errorf("fichier mensuel absent : %v", err)
		}
	}
	sys, _ := s.ReadAfter(KindSystem, 0, 10)
	if len(sys) != 2 || sys[0].Message != "fin octobre" || sys[1].Message != "début novembre" {
		t.Fatalf("logs système = %+v", sys)
	}
	if acc, _ := s.ReadAfter(KindAccess, 0, 10); len(acc) != 1 {
		t.Fatalf("les accès voient %d lignes, attendu 1 (types séparés)", len(acc))
	}
}

func TestPseudonymizedIPIsEncryptedAndNeverWrittenInClear(t *testing.T) {
	k := key(t)
	s := openTest(t, func(o *Options) { o.IPKey = k })
	const real = "203.0.113.42"
	e := access(at("2026-10-21T10:00:00Z"), "203.0.113.0")
	e.IPTruncated, e.RealIP = true, real
	s.Add(KindAccess, e)
	s.Flush()

	rows, _ := s.ReadAfter(KindAccess, 0, 1)
	if len(rows) != 1 || rows[0].IP != "203.0.113.0" || !rows[0].Pseudonymized || !rows[0].IPTruncated {
		t.Fatalf("ligne pseudonymisée = %+v", rows)
	}
	if got, err := s.RevealIP(KindAccess, rows[0].ID); err != nil || got != real {
		t.Fatalf("RevealIP = %q, %v", got, err)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if grepDir(t, s.opts.Dir, real) {
		t.Fatalf("l'IP réelle %s est écrite en clair dans la base", real)
	}
}

func TestRealIPIsIgnoredWithoutAKey(t *testing.T) {
	s := openTest(t)
	e := access(at("2026-10-21T10:00:00Z"), "203.0.113.0")
	e.RealIP = "203.0.113.42"
	s.Add(KindAccess, e)
	s.Flush()

	rows, _ := s.ReadAfter(KindAccess, 0, 1)
	if len(rows) != 1 || rows[0].Pseudonymized {
		t.Fatalf("sans clé, la ligne ne doit rien garder de l'IP réelle : %+v", rows)
	}
	if _, err := s.RevealIP(KindAccess, rows[0].ID); err != ErrNotPseudonymized {
		t.Fatalf("RevealIP sans clé = %v, attendu ErrNotPseudonymized", err)
	}
	_ = s.Close()
	if grepDir(t, s.opts.Dir, "203.0.113.42") {
		t.Fatal("l'IP réelle est écrite alors que la base n'a pas de clé")
	}
}

func TestRevealIPNeedsTheKey(t *testing.T) {
	k := key(t)
	dir := filepath.Join(t.TempDir(), "logs")
	s, err := Open(Options{Dir: dir, IPKey: k})
	if err != nil {
		t.Fatal(err)
	}
	e := access(at("2026-10-21T10:00:00Z"), "203.0.113.0")
	e.RealIP = "203.0.113.42"
	s.Add(KindAccess, e)
	s.Flush()
	rows, _ := s.ReadAfter(KindAccess, 0, 1)
	_ = s.Close()

	s2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if _, err := s2.RevealIP(KindAccess, rows[0].ID); err != ErrNoKey {
		t.Fatalf("RevealIP sans clé = %v, attendu ErrNoKey", err)
	}
	s3, err := Open(Options{Dir: dir, IPKey: k})
	if err != nil {
		t.Fatal(err)
	}
	defer s3.Close()
	if got, err := s3.RevealIP(KindAccess, rows[0].ID); err != nil || got != "203.0.113.42" {
		t.Fatalf("après réouverture avec la clé : %q, %v", got, err)
	}
}

func TestEraseIPRemovesClearAndPseudonymizedRows(t *testing.T) {
	k := key(t)
	s := openTest(t, func(o *Options) { o.IPKey = k })
	const target = "203.0.113.42"
	s.Add(KindAccess, access(at("2026-10-14T08:00:00Z"), target))
	s.Add(KindAccess, access(at("2026-10-14T08:00:01Z"), "2001:db8::1"))
	pseudo := access(at("2026-10-21T08:00:00Z"), "203.0.113.0")
	pseudo.RealIP, pseudo.IPTruncated = target, true
	s.Add(KindAccess, pseudo)
	other := access(at("2026-10-21T08:00:01Z"), "198.51.100.7")
	other.RealIP, other.IPTruncated = "198.51.100.7", true
	s.Add(KindAccess, other)
	s.Flush()

	n, err := s.EraseIP(" " + target + " ")
	if err != nil || n != 2 {
		t.Fatalf("EraseIP = %d lignes, %v ; attendu 2 (une en clair, une pseudonymisée, dans deux fichiers)", n, err)
	}
	rows, _ := s.ReadAfter(KindAccess, 0, 10)
	if len(rows) != 2 {
		t.Fatalf("il reste %d lignes, attendu 2 (les autres IP)", len(rows))
	}
	for _, r := range rows {
		if r.IP == target {
			t.Fatalf("ligne de l'IP effacée encore présente : %+v", r)
		}
	}
	if n, _ := s.EraseIP("not-an-ip-at-all"); n != 0 {
		t.Fatalf("effacement d'une valeur inconnue = %d lignes", n)
	}
	if n, _ := s.EraseIP(""); n != 0 {
		t.Fatalf("effacement d'une IP vide = %d lignes", n)
	}

	_ = s.Close()
	if grepDir(t, s.opts.Dir, target) {
		t.Fatalf("l'IP effacée %s reste lisible dans les fichiers de la base", target)
	}
}

func TestPurgeDropsWholeFilesAndTrimsTheBoundaryFile(t *testing.T) {
	now := at("2027-10-21T12:00:00Z")
	s := openTest(t, func(o *Options) {
		o.Now = func() time.Time { return now }
		o.Retention = map[Kind]time.Duration{KindAccess: 365 * 24 * time.Hour, KindSystem: 90 * 24 * time.Hour}
	})
	// Limite d'accès : 2026-10-21T12:00. La semaine du 2026-10-19 la chevauche ; celle du 2026-10-05 est finie avant.
	s.Add(KindAccess, access(at("2026-10-07T08:00:00Z"), "198.51.100.1")) // fichier à supprimer
	s.Add(KindAccess, access(at("2026-10-20T08:00:00Z"), "198.51.100.2")) // fichier à cheval, ligne trop vieille
	s.Add(KindAccess, access(at("2026-10-22T08:00:00Z"), "198.51.100.3")) // fichier à cheval, ligne gardée
	s.Add(KindAccess, access(at("2027-10-20T08:00:00Z"), "198.51.100.4")) // fichier récent
	s.Add(KindSystem, Entry{Ts: at("2027-06-15T08:00:00Z"), Level: "info", Message: "trop vieux"})
	s.Add(KindSystem, Entry{Ts: at("2027-09-15T08:00:00Z"), Level: "info", Message: "récent"})
	s.Flush()

	s.Purge(now)

	if _, err := os.Stat(filepath.Join(s.opts.Dir, "access-2026-10-05.db")); !os.IsNotExist(err) {
		t.Errorf("le fichier plus vieux que la rétention doit être supprimé : %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.opts.Dir, "system-2027-06.db")); !os.IsNotExist(err) {
		t.Errorf("le fichier système expiré doit être supprimé : %v", err)
	}
	rows, _ := s.ReadAfter(KindAccess, 0, 10)
	var ips []string
	for _, r := range rows {
		ips = append(ips, r.IP)
	}
	if strings.Join(ips, ",") != "198.51.100.3,198.51.100.4" {
		t.Fatalf("lignes restantes = %v, attendu la ligne gardée du fichier à cheval et le fichier récent", ips)
	}
	if sys, _ := s.ReadAfter(KindSystem, 0, 10); len(sys) != 1 || sys[0].Message != "récent" {
		t.Fatalf("logs système restants = %+v", sys)
	}
}

func TestWriteFailureDropsLinesWithoutBlockingAndReportsOnce(t *testing.T) {
	var reported []error
	s := openTest(t, func(o *Options) {
		o.OnError = func(err error) { reported = append(reported, err) }
		o.Now = func() time.Time { return at("2026-10-21T10:00:00Z") }
	})
	// La base devient inutilisable : le dossier est remplacé par un fichier.
	if err := os.RemoveAll(s.opts.Dir); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.opts.Dir, []byte("pas un dossier"), 0o644); err != nil {
		t.Fatal(err)
	}

	start := time.Now()
	for i := 0; i < 50; i++ {
		s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1"))
		if i%10 == 9 {
			s.Flush()
		}
	}
	if d := time.Since(start); d > 5*time.Second {
		t.Fatalf("l'écriture en échec a ralenti l'appelant : %v", d)
	}
	if s.Dropped() != 50 {
		t.Fatalf("Dropped = %d, attendu 50", s.Dropped())
	}
	if len(reported) != 1 {
		t.Fatalf("%d erreurs remontées, attendu 1 par minute", len(reported))
	}
}

func TestAddNeverBlocksWhenTheQueueIsFull(t *testing.T) {
	s := openTest(t, func(o *Options) { o.QueueSize = 1; o.FlushEvery = time.Hour; o.BatchSize = 1 << 20 })
	done := make(chan struct{})
	go func() {
		defer close(done)
		for i := 0; i < 20000; i++ {
			s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1"))
		}
	}()
	select {
	case <-done:
	case <-time.After(10 * time.Second):
		t.Fatal("Add a bloqué sur une file pleine")
	}
	if s.Dropped() == 0 {
		t.Error("aucune ligne perdue alors que la file de 1 est saturée")
	}
}

func BenchmarkAddAndFlush(b *testing.B) {
	s, err := Open(Options{Dir: filepath.Join(b.TempDir(), "logs"), IPKey: bytes.Repeat([]byte{1}, ipcrypt.KeySize), QueueSize: 1 << 20})
	if err != nil {
		b.Fatal(err)
	}
	defer s.Close()
	e := access(time.Now(), "203.0.113.0")
	e.RealIP = "203.0.113.42"
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		s.Add(KindAccess, e)
	}
	s.Flush()
	b.StopTimer()
	if s.Dropped() != 0 {
		b.Fatalf("%d lignes perdues", s.Dropped())
	}
}

func TestAddAfterCloseIsRefused(t *testing.T) {
	s := openTest(t)
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1")) {
		t.Fatal("Add accepté sur une base fermée")
	}
	s.Flush() // ne doit pas bloquer
}

func TestCloseWritesWhatIsPending(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	s, err := Open(Options{Dir: dir, FlushEvery: time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 10; i++ {
		s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1"))
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	s2, err := Open(Options{Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	if rows, _ := s2.ReadAfter(KindAccess, 0, 100); len(rows) != 10 {
		t.Fatalf("après réouverture : %d lignes, attendu 10", len(rows))
	}
}

func TestPeriodIndexGrowsAndFileNamesRoundTrip(t *testing.T) {
	var prev int64 = -1
	for _, d := range []string{"2026-10-12", "2026-10-19", "2026-10-26", "2026-11-02", "2027-01-04"} {
		start, _ := time.Parse("2006-01-02", d)
		if idx := KindAccess.periodIndex(start); idx <= prev {
			t.Errorf("index non croissant à %s : %d après %d", d, idx, prev)
		} else {
			prev = idx
		}
		if k, got, ok := parseFileName(KindAccess.fileName(start)); !ok || k != KindAccess || !got.Equal(start) {
			t.Errorf("nom de fichier %s non relu : %v %v %v", KindAccess.fileName(start), k, got, ok)
		}
	}
	// Un mardi n'est pas un début de semaine : le nom est refusé.
	if _, _, ok := parseFileName("access-2026-10-13.db"); ok {
		t.Error("access-2026-10-13.db (un mardi) accepté comme fichier de période")
	}
	if _, _, ok := parseFileName("access-2026-10-12.db-wal"); ok {
		t.Error("un fichier -wal pris pour une base")
	}
	if got := KindAccess.periodStart(at("2026-10-25T23:59:59Z")); got.Format("2006-01-02") != "2026-10-19" {
		t.Errorf("dimanche 2026-10-25 : semaine du %s, attendu 2026-10-19", got.Format("2006-01-02"))
	}
}

// grepDir cherche une valeur dans tous les fichiers du dossier (bases, WAL, index).
func grepDir(t *testing.T, dir, needle string) bool {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, de := range entries {
		b, err := os.ReadFile(filepath.Join(dir, de.Name()))
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(b, []byte(needle)) {
			t.Logf("%q trouvé dans %s", needle, de.Name())
			return true
		}
	}
	return false
}

func TestReadAfterRevealedFillsTheRealIPOnlyWhenAsked(t *testing.T) {
	s := openTest(t, func(o *Options) { o.IPKey = key(t) })
	e := access(at("2026-10-21T10:00:00Z"), "203.0.113.0")
	e.RealIP, e.IPTruncated = "203.0.113.42", true
	s.Add(KindAccess, e)
	s.Add(KindAccess, access(at("2026-10-21T10:00:01Z"), "198.51.100.9"))
	s.Flush()

	plain, _ := s.ReadAfter(KindAccess, 0, 10)
	if plain[0].RealIP != "" {
		t.Fatalf("ReadAfter ne doit jamais déchiffrer : %q", plain[0].RealIP)
	}
	revealed, err := s.ReadAfterRevealed(KindAccess, 0, 10)
	if err != nil || len(revealed) != 2 {
		t.Fatalf("ReadAfterRevealed = %d lignes, %v", len(revealed), err)
	}
	if revealed[0].RealIP != "203.0.113.42" || revealed[0].IP != "203.0.113.0" || revealed[1].RealIP != "" {
		t.Fatalf("IP réelle = %q / %q, attendu 203.0.113.42 puis vide", revealed[0].RealIP, revealed[1].RealIP)
	}
}

func TestChangedFiresOnTheNextWriteAndNeverMissesOne(t *testing.T) {
	s := openTest(t)
	ch := s.Changed()
	select {
	case <-ch:
		t.Fatal("signal avant toute écriture")
	default:
	}
	s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1"))
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal("aucun signal après une écriture")
	}
	// Un canal obtenu avant une écriture est fermé par elle, même si le lecteur lit entre-temps.
	next := s.Changed()
	s.Add(KindSystem, Entry{Ts: at("2026-10-21T10:00:00Z"), Message: "x"})
	select {
	case <-next:
	case <-time.After(5 * time.Second):
		t.Fatal("signal manqué")
	}
}

// Une lecture qui arrive après Close ne doit pas rouvrir un fichier : il resterait ouvert pour toujours.
func TestNothingReopensAFileAfterClose(t *testing.T) {
	s := openTest(t)
	s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1"))
	s.Flush()
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if _, err := s.ReadAfter(KindAccess, 0, 10); err != ErrClosed {
		t.Fatalf("lecture après Close = %v, attendu ErrClosed", err)
	}
	if _, err := s.RevealIP(KindAccess, 1<<idShift|1); err == nil {
		t.Fatal("RevealIP après Close doit échouer")
	}
	// Le dossier doit pouvoir être supprimé : aucun fichier n'est resté ouvert.
	if err := os.RemoveAll(s.opts.Dir); err != nil {
		t.Fatalf("fichier resté ouvert après Close : %v", err)
	}
}
