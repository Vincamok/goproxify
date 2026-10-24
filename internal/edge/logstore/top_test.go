// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package logstore

import (
	"context"
	"fmt"
	"sort"
	"strings"
	"testing"
	"time"
)

// seedTop écrit des accès biaisés sur trois semaines (donc trois fichiers) : /p/0 plus fréquent que /p/1, etc.
func seedTop(t *testing.T, s *Store) []Entry {
	t.Helper()
	base := at("2026-10-12T12:00:00Z")
	var all []Entry
	for i := 0; i < 600; i++ {
		e := access(base.Add(time.Duration(i)*50*time.Minute), fmt.Sprintf("198.51.100.%d", 1+i%40))
		e.Path = fmt.Sprintf("/p/%d", (i*i)%23)
		e.Domain = []string{"a.example.com", "b.example.com", "c.example.com"}[i%3]
		e.Status = []int{200, 200, 404, 502}[i%4]
		e.Bytes = int64(100 + i%7)
		e.LatencyMs = int64(i % 11)
		e.Referrer = []string{"", "https://x.example/", "https://y.example/"}[i%3]
		e.TLSJA4 = []string{"", "t13d1", "t13d2", "t13d3"}[i%4]
		e.TLSJA3 = "ja3-" + e.TLSJA4
		if i%9 == 0 {
			e.IP, e.IPTruncated = "203.0.113.0", true
		}
		if i%10 != 0 {
			e.WAFMatches, e.ThreatSignal = nil, ""
		}
		s.Add(KindAccess, e)
		all = append(all, e)
	}
	s.Flush()
	return all
}

type oracleItem struct {
	value                          string
	req, errs, bytes, lat, flagged int64
	trunc                          bool
}

func oracle(entries []Entry, dim string, keep func(Entry) bool) []oracleItem {
	by := map[string]*oracleItem{}
	for _, e := range entries {
		if !keep(e) {
			continue
		}
		var v string
		switch dim {
		case "path":
			v = e.Path
		case "ip":
			v = e.IP
		case "domain":
			v = e.Domain
		case "referrer":
			v = e.Referrer
		case "tls_ja4":
			v = e.TLSJA4
		case "status":
			v = fmt.Sprint(e.Status)
		}
		if (dim == "referrer" || dim == "tls_ja4") && v == "" {
			continue
		}
		it := by[v]
		if it == nil {
			it = &oracleItem{value: v}
			by[v] = it
		}
		it.req++
		if e.Status >= 400 {
			it.errs++
		}
		it.bytes += e.Bytes
		it.lat += e.LatencyMs
		if e.ThreatSignal != "" || len(e.WAFMatches) > 0 {
			it.flagged++
		}
		it.trunc = it.trunc || e.IPTruncated
	}
	out := make([]oracleItem, 0, len(by))
	for _, it := range by {
		out = append(out, *it)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].req != out[j].req {
			return out[i].req > out[j].req
		}
		return out[i].value < out[j].value
	})
	return out
}

func sameItems(t *testing.T, name string, got []TopItem, want []oracleItem) {
	t.Helper()
	if len(got) != len(want) {
		t.Errorf("%s : %d valeurs, attendu %d", name, len(got), len(want))
		return
	}
	for i := range got {
		g, w := got[i], want[i]
		if g.Value != w.value || g.Requests != w.req || g.Errors != w.errs || g.Bytes != w.bytes || g.LatencySum != w.lat ||
			g.Flagged != w.flagged || g.Truncated != w.trunc {
			t.Errorf("%s : rang %d = %+v, attendu %+v", name, i, g, w)
			return
		}
	}
}

func TestTopBestMatchesAGroupByOverEveryFile(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	all := func(Entry) bool { return true }
	for _, dim := range []string{"path", "ip", "domain", "referrer", "tls_ja4", "status"} {
		want := oracle(entries, dim, all)
		for _, k := range []int{1, 3, 7, 1000} {
			res, err := s.Top(context.Background(), Query{}, TopRequest{Dim: dim, Mode: TopBest, K: k})
			if err != nil {
				t.Fatal(err)
			}
			w := want
			if len(w) > k {
				w = w[:k]
			}
			sameItems(t, fmt.Sprintf("%s k=%d", dim, k), res.Items, w)
			if res.Complete != (len(want) <= k) {
				t.Errorf("%s k=%d : Complete=%v avec %d valeurs au total", dim, k, res.Complete, len(want))
			}
		}
	}
}

func TestTopOnASingleFileUsesTheSameRanking(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	from, to := at("2026-10-12T12:00:00Z"), at("2026-10-14T12:00:00Z")
	keep := func(e Entry) bool { return !e.Ts.Before(from) && !e.Ts.After(to) }
	want := oracle(entries, "path", keep)
	res, err := s.Top(context.Background(), Query{From: from, To: to}, TopRequest{Dim: "path", Mode: TopBest, K: 5})
	if err != nil {
		t.Fatal(err)
	}
	sameItems(t, "une semaine", res.Items, want[:5])
}

func TestTopAboveAndExactAgreeWithTheRanking(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	want := oracle(entries, "path", func(Entry) bool { return true })
	min := want[4].req
	var above []oracleItem
	for _, it := range want {
		if it.req >= min {
			above = append(above, it)
		}
	}
	res, err := s.Top(context.Background(), Query{}, TopRequest{Dim: "path", Mode: TopAbove, Min: min})
	if err != nil {
		t.Fatal(err)
	}
	sameItems(t, "au-dessus du seuil", res.Items, above)

	values := []string{want[0].value, want[len(want)-1].value, "/absent"}
	res, err = s.Top(context.Background(), Query{}, TopRequest{Dim: "path", Mode: TopExact, Values: values})
	if err != nil {
		t.Fatal(err)
	}
	sameItems(t, "comptes exacts", res.Items, []oracleItem{want[0], want[len(want)-1]})
}

func TestTopHonoursTheFilters(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	keep := func(e Entry) bool { return (e.Domain == "a.example.com" || e.Domain == "c.example.com") && strings.HasPrefix(e.Path, "/p/1") }
	want := oracle(entries, "ip", keep)
	res, err := s.Top(context.Background(), Query{Domains: []string{"a.example.com", "c.example.com"}, PathPrefix: "/p/1"},
		TopRequest{Dim: "ip", Mode: TopBest, K: 1000})
	if err != nil {
		t.Fatal(err)
	}
	sameItems(t, "domaines et préfixe", res.Items, want)
}

func TestTopIgnoresSystemLinesAndRejectsUnknownDimensions(t *testing.T) {
	s := openTest(t)
	seedTop(t, s)
	s.Add(KindSystem, Entry{Ts: at("2026-10-13T00:00:00Z"), Level: "info", Component: "edge", Message: "démarrage", Path: "/sys", Status: 200, IP: "1.1.1.1"})
	s.Flush()
	res, err := s.Top(context.Background(), Query{}, TopRequest{Dim: "path", Mode: TopExact, Values: []string{"/sys"}})
	if err != nil || len(res.Items) != 0 {
		t.Fatalf("une ligne système ne doit pas compter : %+v %v", res.Items, err)
	}
	if _, err := s.Top(context.Background(), Query{}, TopRequest{Dim: "message", Mode: TopBest, K: 3}); err == nil {
		t.Error("une dimension inconnue devrait être refusée")
	}
}

// Le résumé d'IP d'une empreinte TLS ne contient que les IP attribuables : ni tronquées ni pseudonymisées.
func TestTopExactCanCarryTheAttributableIPsOfEachValue(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	res, err := s.Top(context.Background(), Query{}, TopRequest{Dim: "tls_ja4", Mode: TopExact, Values: []string{"t13d1", "t13d2"}, WithIPs: true})
	if err != nil {
		t.Fatal(err)
	}
	for _, it := range res.Items {
		want := map[string]bool{}
		for _, e := range entries {
			if e.TLSJA4 == it.Value && !e.IPTruncated {
				want[e.IP] = true
			}
		}
		if it.IPs == nil || len(it.IPs.Exact) != len(want) {
			t.Errorf("%s : %v IP, attendu %d", it.Value, it.IPs, len(want))
			continue
		}
		for _, ip := range it.IPs.Exact {
			if !want[ip] {
				t.Errorf("%s : IP inattendue %s", it.Value, ip)
			}
		}
	}
}

func TestUniqueIPsCoversTheWholePeriod(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	want := map[string]bool{}
	for _, e := range entries {
		want[e.IP] = true
	}
	sum, partial, err := s.UniqueIPs(context.Background(), Query{})
	if err != nil || partial {
		t.Fatal(err, partial)
	}
	if len(sum.Exact) != len(want) {
		t.Errorf("%d IP distinctes, attendu %d", len(sum.Exact), len(want))
	}
	from := at("2026-10-12T12:00:00Z")
	sum, _, _ = s.UniqueIPs(context.Background(), Query{From: from, To: from.Add(30 * time.Minute)})
	if len(sum.Exact) != 1 {
		t.Errorf("une seule requête dans la fenêtre, %d IP", len(sum.Exact))
	}
}

func TestTopStopsAtTheDeadlineAndSaysSo(t *testing.T) {
	s := openTest(t)
	seedTop(t, s)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	res, err := s.Top(ctx, Query{}, TopRequest{Dim: "path", Mode: TopBest, K: 3})
	if err != nil {
		t.Fatal(err)
	}
	if !res.Partial || res.Complete {
		t.Errorf("Partial=%v Complete=%v, attendu partiel et incomplet", res.Partial, res.Complete)
	}
}

func TestTopCountsBlockedAndSuccessfulRequestsPerIP(t *testing.T) {
	s := openTest(t)
	base := at("2026-10-21T10:00:00Z")
	add := func(i int, ip string, status int, waf []string, signal string) {
		e := access(base.Add(time.Duration(i)*time.Second), ip)
		e.Status, e.WAFMatches, e.ThreatSignal = status, waf, signal
		s.Add(KindAccess, e)
	}
	add(0, "203.0.113.5", 200, nil, "")
	add(1, "203.0.113.5", 403, nil, "")
	add(2, "203.0.113.5", 200, []string{"sqli"}, "")
	add(3, "203.0.113.5", 301, nil, "")
	add(4, "203.0.113.5", 500, nil, "")
	add(5, "203.0.113.5", 429, nil, "")
	add(6, "203.0.113.5", 200, nil, "scan")
	s.Flush()
	res, err := s.Top(context.Background(), Query{}, TopRequest{Dim: "ip", Mode: TopBest, K: 5})
	if err != nil || len(res.Items) != 1 {
		t.Fatal(res.Items, err)
	}
	it := res.Items[0]
	// bloquées : 403, 200+WAF, 429, 200+signal ; réussies non bloquées : 200, 301 ; la 500 n'est ni l'une ni l'autre.
	if it.Requests != 7 || it.Blocked != 4 || it.Ok != 2 {
		t.Errorf("requêtes=%d bloquées=%d réussies=%d, attendu 7/4/2", it.Requests, it.Blocked, it.Ok)
	}
	if it.FirstSeen != base.UTC().Format(tsLayout) || it.LastSeen != base.Add(6*time.Second).UTC().Format(tsLayout) {
		t.Errorf("premier/dernier passage = %s / %s", it.FirstSeen, it.LastSeen)
	}
}

func TestTopAllGivesTheTotalsOfTheSelectionAcrossFiles(t *testing.T) {
	s := openTest(t)
	entries := seedTop(t, s)
	res, err := s.Top(context.Background(), Query{Domains: []string{"a.example.com"}}, TopRequest{Dim: "all", Mode: TopBest, K: 1})
	if err != nil || len(res.Items) != 1 {
		t.Fatal(res.Items, err)
	}
	want := oracle(entries, "domain", func(e Entry) bool { return e.Domain == "a.example.com" })[0]
	if res.Items[0].Requests != want.req || res.Items[0].Errors != want.errs || res.Items[0].Bytes != want.bytes {
		t.Errorf("totaux = %+v, attendu %+v", res.Items[0], want)
	}
	var first, last time.Time
	for _, e := range entries {
		if e.Domain != "a.example.com" {
			continue
		}
		if first.IsZero() || e.Ts.Before(first) {
			first = e.Ts
		}
		if e.Ts.After(last) {
			last = e.Ts
		}
	}
	if res.Items[0].FirstSeen != first.UTC().Format(tsLayout) || res.Items[0].LastSeen != last.UTC().Format(tsLayout) {
		t.Errorf("premier/dernier = %s / %s", res.Items[0].FirstSeen, res.Items[0].LastSeen)
	}
}

func TestIPRangeFiltersKeepASupersetOfTheRange(t *testing.T) {
	s := openTest(t)
	base := at("2026-10-21T10:00:00Z")
	for i, ip := range []string{"10.1.2.3", "10.1.9.9", "10.2.0.1", "192.168.0.1", "2001:db8:1::5"} {
		s.Add(KindAccess, access(base.Add(time.Duration(i)*time.Second), ip))
	}
	s.Flush()
	count := func(q Query) int {
		q.Limit = 100
		p, err := s.Search(context.Background(), q)
		if err != nil {
			t.Fatal(err)
		}
		return len(p.Rows)
	}
	if n := count(Query{IPFrom: "10.1.", IPTo: "10.1." + "\x7f"}); n != 2 {
		t.Errorf("plage 10.1. : %d lignes, attendu 2", n)
	}
	if n := count(Query{IPRanges: [][2]string{{"10.1.", "10.1.\x7f"}, {"192.168.", "192.168.\x7f"}}}); n != 3 {
		t.Errorf("deux plages : %d lignes, attendu 3", n)
	}
	res, err := s.Top(context.Background(), Query{IPRanges: [][2]string{{"10.2.", "10.2.\x7f"}}}, TopRequest{Dim: "ip", Mode: TopBest, K: 10})
	if err != nil || len(res.Items) != 1 || res.Items[0].Value != "10.2.0.1" {
		t.Errorf("regroupement sur une plage : %+v %v", res.Items, err)
	}
}

func TestRecentCountsCoverTheWindowAcrossFiles(t *testing.T) {
	s := openTest(t)
	now := time.Now().UTC()
	add := func(age time.Duration, status int) {
		e := access(now.Add(-age), "198.51.100.1")
		e.Status = status
		s.Add(KindAccess, e)
	}
	for i := 0; i < 5; i++ {
		add(10*time.Second, 200)
	}
	add(20*time.Second, 403)
	add(20*time.Second, 429)
	add(30*time.Second, 502)
	add(2*time.Minute, 500) // hors fenêtre
	add(9*24*time.Hour, 403)
	s.Flush()
	total, blocked, errs, err := s.RecentCounts(context.Background(), now.Add(-time.Minute))
	if err != nil || total != 8 || blocked != 2 || errs != 1 {
		t.Errorf("total=%d refusées=%d erreurs=%d (%v), attendu 8/2/1", total, blocked, errs, err)
	}
}
