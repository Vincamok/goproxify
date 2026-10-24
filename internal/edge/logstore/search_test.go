// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"fmt"
	"sort"
	"testing"
	"time"
)

// seed écrit n requêtes espacées de step à partir de start, sur plusieurs semaines si besoin.
func seed(s *Store, start time.Time, n int, step time.Duration, mutate func(i int, e *Entry)) {
	for i := 0; i < n; i++ {
		e := access(start.Add(time.Duration(i)*step), "198.51.100.1")
		e.Path = fmt.Sprintf("/p/%04d", i)
		if mutate != nil {
			mutate(i, &e)
		}
		s.Add(KindAccess, e)
	}
	s.Flush()
}

func paths(rows []Row) []string {
	out := make([]string, len(rows))
	for i, r := range rows {
		out[i] = r.Path
	}
	return out
}

func TestSearchFiltersLikeTheAdminOnes(t *testing.T) {
	s := openTest(t)
	seed(s, at("2026-10-21T10:00:00Z"), 12, time.Minute, func(i int, e *Entry) {
		e.Domain = []string{"a.example.com", "b.example.com"}[i%2]
		e.Status = []int{200, 404, 502}[i%3]
		e.Level = map[int]string{200: "info", 404: "warn", 502: "error"}[e.Status]
		e.Method = []string{"GET", "POST"}[(i/2)%2]
		if i == 5 {
			e.UserAgent = "SuperScanner/1.0"
		}
	})
	count := func(q Query) int {
		t.Helper()
		q.Limit = 100
		p, err := s.Search(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Rows)
	}
	cases := []struct {
		name string
		q    Query
		want int
	}{
		{"tout", Query{}, 12},
		{"domaine", Query{Domain: "a.example.com"}, 6},
		{"classe 5xx", Query{Status: "5xx"}, 4},
		{"code exact", Query{Status: "404"}, 4},
		{"niveau", Query{Level: "error"}, 4},
		{"méthode", Query{Method: "POST"}, 6},
		{"chemin", Query{Path: "/p/000"}, 10},
		{"texte libre dans l'agent utilisateur", Query{Search: "scanner"}, 1},
		{"texte libre dans le chemin", Query{Search: "p/0011"}, 1},
		{"depuis", Query{From: at("2026-10-21T10:06:00Z")}, 6},
		{"jusqu'à", Query{To: at("2026-10-21T10:03:00Z")}, 4},
		{"combiné", Query{Domain: "a.example.com", Status: "4xx"}, 2},
		{"aucun", Query{Domain: "absent.example.com"}, 0},
		{"request_id exact", Query{RequestID: "req-1"}, 12},
	}
	for _, c := range cases {
		if got := count(c.q); got != c.want {
			t.Errorf("%s : %d lignes, attendu %d", c.name, got, c.want)
		}
	}
}

// Une page après l'autre, avec des horodatages identiques et à travers trois semaines : chaque ligne une fois, dans
// l'ordre du plus récent au plus ancien.
func TestSearchPagesThroughFilesAndEqualTimestampsWithoutLossOrDuplicates(t *testing.T) {
	s := openTest(t)
	base := at("2026-10-12T12:00:00Z") // semaine du 12, puis 19, puis 26
	seed(s, base, 60, 8*time.Hour, func(i int, e *Entry) {
		if i%7 == 0 && i > 0 { // des paquets de lignes au même instant
			e.Ts = base.Add(time.Duration(i-1) * 8 * time.Hour)
		}
	})
	want := map[string]bool{}
	for i := 0; i < 60; i++ {
		want[fmt.Sprintf("/p/%04d", i)] = true
	}

	var seen []string
	q := Query{Limit: 7}
	for pages := 0; pages < 100; pages++ {
		p, err := s.Search(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		seen = append(seen, paths(p.Rows)...)
		if !p.HasMore {
			break
		}
		q.After = p.Next
	}
	if len(seen) != 60 {
		t.Fatalf("%d lignes parcourues, attendu 60", len(seen))
	}
	dup := map[string]bool{}
	for _, p := range seen {
		if dup[p] || !want[p] {
			t.Fatalf("ligne en double ou inconnue : %s", p)
		}
		dup[p] = true
	}
	// Du plus récent au plus ancien : les horodatages ne remontent jamais.
	all, _ := s.Search(context.Background(), Query{Limit: 100})
	for i := 1; i < len(all.Rows); i++ {
		if all.Rows[i].Ts.After(all.Rows[i-1].Ts) {
			t.Fatalf("ordre rompu à la ligne %d", i)
		}
	}
	if len(s.files(KindAccess)) < 3 {
		t.Fatalf("%d fichiers, le test doit couvrir au moins 3 semaines", len(s.files(KindAccess)))
	}
}

func TestSearchMergesAccessAndSystemLinesByTime(t *testing.T) {
	s := openTest(t)
	for i := 0; i < 5; i++ {
		ts := at("2026-10-21T10:00:00Z").Add(time.Duration(2*i) * time.Second)
		s.Add(KindAccess, access(ts, "198.51.100.1"))
		s.Add(KindSystem, Entry{Ts: ts.Add(time.Second), Level: "info", Component: "edge", Message: fmt.Sprintf("sys-%d", i)})
	}
	s.Flush()
	var got []string
	q := Query{Limit: 3}
	for {
		p, err := s.Search(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		for _, r := range p.Rows {
			got = append(got, r.Ts.Format("05"))
		}
		if !p.HasMore {
			break
		}
		q.After = p.Next
	}
	if len(got) != 10 {
		t.Fatalf("%d lignes, attendu 10 : %v", len(got), got)
	}
	if !sort.IsSorted(sort.Reverse(sort.StringSlice(got))) {
		t.Fatalf("les deux types ne sont pas fusionnés par date : %v", got)
	}
	only, _ := s.Search(context.Background(), Query{Kinds: []Kind{KindSystem}, Limit: 100})
	if len(only.Rows) != 5 {
		t.Fatalf("type système seul : %d lignes", len(only.Rows))
	}
}

// Chercher une IP retrouve aussi les lignes pseudonymisées, par leur empreinte.
func TestSearchByIPFindsPseudonymizedLines(t *testing.T) {
	s := openTest(t, func(o *Options) { o.IPKey = key(t) })
	clear := access(at("2026-10-21T10:00:00Z"), "203.0.113.42")
	pseudo := access(at("2026-10-21T10:00:01Z"), "203.0.113.0")
	pseudo.RealIP, pseudo.IPTruncated = "203.0.113.42", true
	other := access(at("2026-10-21T10:00:02Z"), "198.51.100.9")
	s.Add(KindAccess, clear)
	s.Add(KindAccess, pseudo)
	s.Add(KindAccess, other)
	s.Flush()

	p, err := s.Search(context.Background(), Query{IP: " 203.0.113.42 ", Limit: 10})
	if err != nil || len(p.Rows) != 2 {
		t.Fatalf("%d lignes pour l'IP, %v ; attendu 2 (en clair et pseudonymisée)", len(p.Rows), err)
	}
}

func TestSearchCanExcludeInternalAddresses(t *testing.T) {
	s := openTest(t)
	for i, ip := range []string{"10.0.0.5", "192.168.1.1", "172.20.0.3", "127.0.0.1", "::1", "203.0.113.5", "2001:db8::1"} {
		s.Add(KindAccess, access(at("2026-10-21T10:00:00Z").Add(time.Duration(i)*time.Second), ip))
	}
	s.Flush()
	p, _ := s.Search(context.Background(), Query{ExcludeInternal: true, Limit: 100})
	if len(p.Rows) != 2 {
		t.Fatalf("%d lignes publiques, attendu 2", len(p.Rows))
	}
}

// Un délai écoulé ne fait pas échouer la recherche : elle rend ce qu'elle a et se dit partielle.
func TestSearchReportsAPartialResultWhenTheContextExpires(t *testing.T) {
	s := openTest(t)
	seed(s, at("2026-10-21T10:00:00Z"), 20, time.Second, nil)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	p, err := s.Search(ctx, Query{Limit: 10})
	if err != nil {
		t.Fatalf("une recherche interrompue ne doit pas échouer : %v", err)
	}
	if !p.Partial {
		t.Fatal("la recherche aurait dû se dire partielle")
	}
}

func TestHistogramBucketsByLevelAndShiftsToTheRequestedZone(t *testing.T) {
	s := openTest(t)
	for i, st := range []int{200, 404, 502, 200} {
		e := access(at("2026-10-21T22:30:00Z").Add(time.Duration(i)*15*time.Minute), "198.51.100.1")
		e.Status = st
		e.Level = map[int]string{200: "info", 404: "warn", 502: "error"}[st]
		s.Add(KindAccess, e)
	}
	s.Flush()
	utc, partial, err := s.Histogram(context.Background(), Query{}, "hour", 0)
	if err != nil || partial {
		t.Fatalf("histogramme : %v partiel=%v", err, partial)
	}
	if len(utc) != 2 || utc[0].Bucket != "2026-10-21T22:00" || utc[0].Total != 2 || utc[0].Warn != 1 || utc[1].Bucket != "2026-10-21T23:00" || utc[1].Error != 1 {
		t.Fatalf("tranches UTC = %+v", utc)
	}
	// UTC+2 : 22 h UTC devient minuit le lendemain.
	paris, _, _ := s.Histogram(context.Background(), Query{}, "day", 120)
	if len(paris) != 1 || paris[0].Bucket != "2026-10-22" || paris[0].Total != 4 {
		t.Fatalf("tranches du jour à UTC+2 = %+v", paris)
	}
}

func TestFacetsCountTheMostFrequentValues(t *testing.T) {
	s := openTest(t)
	seed(s, at("2026-10-21T10:00:00Z"), 10, time.Second, func(i int, e *Entry) {
		if i < 7 {
			e.Domain = "a.example.com"
		} else {
			e.Domain = "b.example.com"
		}
		e.Method = "GET"
	})
	f, total, partial, err := s.Facets(context.Background(), Query{}, []string{"domain", "method", "inconnu"})
	if err != nil || partial || total != 10 {
		t.Fatalf("facettes : total=%d partiel=%v %v", total, partial, err)
	}
	if d := f["domain"]; len(d) != 2 || d[0].Value != "a.example.com" || d[0].Count != 7 || d[1].Count != 3 {
		t.Fatalf("domaines = %+v", d)
	}
	if _, ok := f["inconnu"]; ok {
		t.Fatal("un champ non facettable doit être ignoré")
	}
}
