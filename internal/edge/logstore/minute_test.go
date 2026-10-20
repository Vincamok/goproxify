// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"fmt"
	"path/filepath"
	"testing"
	"time"
)

// totalsByKey relit les cumuls et les recalcule depuis les lignes brutes du même fichier.
func totalsByKey(t *testing.T, s *Store) (agg, raw map[string][4]int64) {
	t.Helper()
	agg, raw = map[string][4]int64{}, map[string][4]int64{}
	for _, f := range s.files(KindAccess) {
		db, err := s.open(KindAccess, f.start)
		if err != nil {
			t.Fatal(err)
		}
		rows, err := db.Query(`SELECT minute, domain, status, requests, bytes, latency_ms_sum, bots FROM minute`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var m, d string
			var st int
			var v [4]int64
			if err := rows.Scan(&m, &d, &st, &v[0], &v[1], &v[2], &v[3]); err != nil {
				t.Fatal(err)
			}
			agg[fmt.Sprintf("%s|%s|%d", m, d, st)] = v
		}
		rows.Close()
		rows, err = db.Query(`SELECT substr(ts, 1, 16), domain, status, COUNT(*), SUM(bytes), SUM(latency_ms),
			SUM(CASE WHEN lower(user_agent) LIKE '%bot%' OR lower(referrer) LIKE '%bot%' OR lower(path) LIKE '%bot%' THEN 1 ELSE 0 END)
			FROM entries WHERE status > 0 GROUP BY 1, 2, 3`)
		if err != nil {
			t.Fatal(err)
		}
		for rows.Next() {
			var m, d string
			var st int
			var v [4]int64
			if err := rows.Scan(&m, &d, &st, &v[0], &v[1], &v[2], &v[3]); err != nil {
				t.Fatal(err)
			}
			raw[fmt.Sprintf("%s|%s|%d", m, d, st)] = v
		}
		rows.Close()
	}
	return agg, raw
}

// Les cumuls sont écrits avec les lignes : sur un jeu fixe qui couvre plusieurs minutes, domaines, codes, deux
// semaines et plusieurs lots, ils égalent ce que donne un GROUP BY sur les lignes brutes.
func TestMinuteTotalsEqualAGroupByOnTheRawLines(t *testing.T) {
	s := openTest(t, func(o *Options) { o.BatchSize = 7 })
	base := at("2026-10-18T23:58:30Z") // à cheval sur deux semaines et sur plusieurs minutes
	statuses := []int{200, 200, 200, 404, 502, 301}
	for i := 0; i < 400; i++ {
		e := access(base.Add(time.Duration(i)*7*time.Second), "198.51.100.1")
		e.Domain = fmt.Sprintf("d%d.example.com", i%3)
		e.Status = statuses[i%len(statuses)]
		e.Bytes = int64(100 + i)
		e.LatencyMs = int64(i % 50)
		if i%11 == 0 {
			e.UserAgent = "Googlebot/2.1"
		}
		s.Add(KindAccess, e)
	}
	s.Add(KindSystem, Entry{Ts: base, Level: "info", Message: "pas un accès"})
	s.Add(KindAccess, Entry{Ts: base, Component: "edge", Message: "status 0"}) // ignoré par les cumuls
	s.Flush()

	agg, raw := totalsByKey(t, s)
	delete(raw, "") // la ligne de statut 0 est filtrée par status > 0
	if len(agg) == 0 || len(agg) != len(raw) {
		t.Fatalf("%d cumuls pour %d groupes de lignes", len(agg), len(raw))
	}
	for k, want := range raw {
		if got := agg[k]; got != want {
			t.Errorf("%s : cumul %v, lignes brutes %v", k, got, want)
		}
	}
	var total int64
	for _, v := range agg {
		total += v[0]
	}
	if total != 400 {
		t.Fatalf("%d requêtes cumulées, attendu 400", total)
	}
	var bots int64
	for _, v := range agg {
		bots += v[3]
	}
	if bots == 0 {
		t.Fatal("aucun robot compté")
	}
}

func TestReadMinutesAfterResumesAndReturnsTheLatestValue(t *testing.T) {
	now := at("2026-10-21T10:00:00Z")
	clock := now
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return clock } })
	for i := 0; i < 3; i++ {
		e := access(at("2026-10-21T10:00:05Z"), "198.51.100.1")
		e.Domain = fmt.Sprintf("d%d.example.com", i)
		s.Add(KindAccess, e)
	}
	s.Flush()

	first, err := s.ReadMinutesAfter(0, 100)
	if err != nil || len(first) != 3 {
		t.Fatalf("première lecture = %d lignes, %v", len(first), err)
	}
	for i := 1; i < len(first); i++ {
		if first[i].Seq <= first[i-1].Seq {
			t.Fatalf("numéros non croissants : %d puis %d", first[i-1].Seq, first[i].Seq)
		}
	}
	pos := first[len(first)-1].Seq
	if again, _ := s.ReadMinutesAfter(pos, 100); len(again) != 0 {
		t.Fatalf("%d lignes après la dernière position", len(again))
	}

	// Une nouvelle requête sur la même minute et le même domaine : la ligne revient avec la valeur cumulée.
	clock = clock.Add(time.Second)
	e := access(at("2026-10-21T10:00:30Z"), "198.51.100.1")
	e.Domain = "d1.example.com"
	s.Add(KindAccess, e)
	s.Flush()
	upd, _ := s.ReadMinutesAfter(pos, 100)
	if len(upd) != 1 || upd[0].Domain != "d1.example.com" || upd[0].Requests != 2 || upd[0].Seq <= pos {
		t.Fatalf("mise à jour = %+v", upd)
	}

	// Pagination : limit 2 sur toutes les lignes, puis la suite depuis la position atteinte.
	page, _ := s.ReadMinutesAfter(0, 2)
	rest, _ := s.ReadMinutesAfter(page[1].Seq, 100)
	if len(page) != 2 || len(rest) != 1 {
		t.Fatalf("pages de %d puis %d lignes, attendu 2 puis 1", len(page), len(rest))
	}
}

// Une requête tardive met à jour un fichier ancien : son numéro dépasse quand même ceux du fichier récent.
func TestALateRequestInAnOldFileStillGetsALaterSequenceNumber(t *testing.T) {
	clock := at("2026-10-27T10:00:00Z")
	s := openTest(t, func(o *Options) { o.Now = func() time.Time { return clock } })
	s.Add(KindAccess, access(at("2026-10-27T09:59:00Z"), "198.51.100.1")) // semaine du 26
	s.Flush()
	recent, _ := s.ReadMinutesAfter(0, 10)
	pos := recent[0].Seq

	clock = clock.Add(time.Minute)
	s.Add(KindAccess, access(at("2026-10-21T10:00:00Z"), "198.51.100.1")) // semaine du 19, très en retard
	s.Flush()
	got, err := s.ReadMinutesAfter(pos, 10)
	if err != nil || len(got) != 1 || got[0].Minute != "2026-10-21T10:00" {
		t.Fatalf("mise à jour d'un fichier ancien non vue : %+v, %v", got, err)
	}
}

// Après un redémarrage dont l'horloge a reculé, les nouveaux numéros restent au-dessus des anciens.
func TestSequenceNumbersStayAboveThePreviousOnesAfterAClockStepBack(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "logs")
	clock := at("2026-10-21T10:00:00Z")
	s, err := Open(Options{Dir: dir, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	s.Add(KindAccess, access(at("2026-10-21T10:00:05Z"), "198.51.100.1"))
	s.Flush()
	before, _ := s.ReadMinutesAfter(0, 10)
	_ = s.Close()

	clock = clock.Add(-time.Hour) // l'horloge recule
	s2, err := Open(Options{Dir: dir, Now: func() time.Time { return clock }})
	if err != nil {
		t.Fatal(err)
	}
	defer s2.Close()
	s2.Add(KindAccess, access(at("2026-10-21T10:00:20Z"), "198.51.100.1"))
	s2.Flush()
	after, _ := s2.ReadMinutesAfter(0, 10)
	if len(after) != 1 || after[0].Seq <= before[0].Seq {
		t.Fatalf("numéro %d après le redémarrage, doit dépasser %d", after[0].Seq, before[0].Seq)
	}
}
