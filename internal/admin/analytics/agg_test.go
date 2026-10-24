package analytics

import (
	"context"
	"math"
	"database/sql"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

// fixtureLine est une requête du jeu d'essai : les cumuls que les passerelles envoient en sont la somme par minute, et
// l'oracle des tests la recalcule à la main.
type fixtureLine struct {
	at           time.Time
	node, domain string
	status       int
	bytes, lat   int64
}

func aggFixture(t *testing.T) (*sql.DB, time.Time, []fixtureLine) {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	base := time.Date(2026, 3, 10, 8, 0, 0, 0, time.UTC)
	nodes := []string{"edge-a", "edge-b"}
	domains := []string{"a.fr", "b.fr", ""}
	statuses := []int{200, 200, 200, 301, 403, 404, 500, 502}
	var lines []fixtureLine
	for i := 0; i < 600; i++ {
		lines = append(lines, fixtureLine{
			at: base.Add(time.Duration(i)*20*time.Second + 30*time.Second%time.Minute), node: nodes[i%2], domain: domains[i%3],
			status: statuses[i%len(statuses)], bytes: int64(100 + i), lat: int64(5 + i%40),
		})
	}
	for _, l := range lines {
		if _, err := d.Exec(`INSERT INTO logs_minute (minute, node_name, domain, status, requests, bytes, latency_ms_sum) VALUES (?, ?, ?, ?, 1, ?, ?)
			ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + 1, bytes = bytes + excluded.bytes,
			latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum`,
			logs.MinuteKey(l.at), l.node, l.domain, l.status, l.bytes, l.lat); err != nil {
			t.Fatal(err)
		}
	}
	return d, base, lines
}

// expected : ce que les cumuls doivent donner pour p, calculé sur les lignes. La fenêtre est arrondie à la minute et
// inclut les deux bornes.
type expected struct {
	reqs, bytes, errs, serverErrs, latSum int64
	byStatus                              map[int]int64
	byBucket                              map[string]*TimePoint
}

func expect(lines []fixtureLine, p Params, bucketLayout string) expected {
	e := expected{byStatus: map[int]int64{}, byBucket: map[string]*TimePoint{}}
	from, to := logs.MinuteKey(p.From), logs.MinuteKey(p.To)
	domains := map[string]bool{}
	for _, d := range strings.Split(p.Proxy, ",") {
		if d != "" {
			domains[d] = true
		}
	}
	for _, l := range lines {
		m := logs.MinuteKey(l.at)
		if m < from || m > to || (p.NodeName != "" && l.node != p.NodeName) || (len(domains) > 0 && !domains[l.domain]) {
			continue
		}
		e.reqs++
		e.bytes += l.bytes
		e.latSum += l.lat
		if l.status >= 400 {
			e.errs++
		}
		if l.status >= 500 {
			e.serverErrs++
		}
		e.byStatus[l.status]++
		key := l.at.Local().Format(bucketLayout)
		b := e.byBucket[key]
		if b == nil {
			b = &TimePoint{Bucket: key}
			e.byBucket[key] = b
		}
		b.Requests++
		b.Bytes += l.bytes
		if l.status >= 400 {
			b.Errors++
		}
	}
	return e
}

func (e expected) timeline() []TimePoint {
	out := make([]TimePoint, 0, len(e.byBucket))
	for _, b := range e.byBucket {
		out = append(out, *b)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Bucket < out[j].Bucket })
	return out
}

func sameTimeline(a, b []TimePoint) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// Les chiffres globaux de Prism lus dans les cumuls sont ceux des requêtes, pour toutes les fenêtres et tous les filtres
// que les cumuls portent (domaine, passerelle), longues ou courtes.
func TestAggregatesGiveTheTotalsOfTheRequests(t *testing.T) {
	d, base, lines := aggFixture(t)
	ctx := context.Background()
	for name, p := range map[string]Params{
		"deux heures":     {From: base, To: base.Add(2*time.Hour - time.Second)},
		"une passerelle":  {From: base, To: base.Add(2*time.Hour - time.Second), NodeName: "edge-a"},
		"un domaine":      {From: base, To: base.Add(2*time.Hour - time.Second), Proxy: "a.fr"},
		"deux domaines":   {From: base, To: base.Add(2*time.Hour - time.Second), Proxy: "a.fr,b.fr", NodeName: "edge-b"},
		"quinze minutes":  {From: base.Add(10 * time.Minute), To: base.Add(25*time.Minute - time.Second)},
		"cinq minutes":    {From: base.Add(40 * time.Minute), To: base.Add(45*time.Minute - time.Second), NodeName: "edge-b"},
		"une minute":      {From: base.Add(3 * time.Minute), To: base.Add(4*time.Minute - time.Second), Proxy: "a.fr"},
		"aucune ligne":    {From: base.Add(-5 * time.Hour), To: base.Add(-4 * time.Hour)},
		"bornes décalées": {From: base.Add(7*time.Minute + 25*time.Second), To: base.Add(31*time.Minute + 40*time.Second)},
	} {
		want := expect(lines, p, "2006-01-02T15:00")
		k := GetKPIs(d, p)
		if k.Requests != want.reqs || k.Bandwidth != want.bytes {
			t.Errorf("%s : KPIs %d requêtes %d octets, attendu %d / %d", name, k.Requests, k.Bandwidth, want.reqs, want.bytes)
		}
		if want.reqs > 0 {
			if wantRate := 100 * float64(want.errs) / float64(want.reqs); math.Abs(k.ErrorRate-wantRate) > 1e-9 {
				t.Errorf("%s : taux d'erreur %v, attendu %v", name, k.ErrorRate, wantRate)
			}
			if wantLat := float64(want.latSum) / float64(want.reqs); k.AvgLatencyMs != wantLat {
				t.Errorf("%s : latence %v, attendu %v", name, k.AvgLatencyMs, wantLat)
			}
		}
		if got := GetTimeline(d, p, "hour"); !sameTimeline(got, expect(lines, p, "2006-01-02T15:00").timeline()) {
			t.Errorf("%s : courbe par heure %+v, attendu %+v", name, got, want.timeline())
		}
		if got := GetTimeline(d, p, "minute"); !sameTimeline(got, expect(lines, p, "2006-01-02T15:04").timeline()) {
			t.Errorf("%s : courbe par minute différente", name)
		}
		var total int64
		for _, g := range GetStatusGroups(d, p) {
			total += g.Count
			for _, c := range g.Breakdown {
				if c.Count != want.byStatus[c.Code] {
					t.Errorf("%s : code %d : %d, attendu %d", name, c.Code, c.Count, want.byStatus[c.Code])
				}
			}
		}
		if total != want.reqs {
			t.Errorf("%s : %d requêtes dans les codes HTTP, attendu %d", name, total, want.reqs)
		}
		if r, e := countReqErr(ctx, d, p); r != want.reqs || e != want.serverErrs {
			t.Errorf("%s : SLO %d/%d, attendu %d/%d", name, r, e, want.reqs, want.serverErrs)
		}
	}
}

// La minute où commence la période courante ne compte pas aussi dans la période précédente : le delta ne double pas
// cette minute quand la fenêtre ne commence pas sur une minute pleine.
func TestKPIDeltaDoesNotCountTheBoundaryMinuteTwice(t *testing.T) {
	d, base, _ := aggFixture(t)
	p := Params{From: base.Add(30*time.Minute + 20*time.Second), To: base.Add(50*time.Minute + 20*time.Second)}
	cur := GetKPIs(d, p)
	prev := PreviousPeriod(p, true)
	if prev.To != p.From.Truncate(time.Minute).Add(-time.Second) {
		t.Fatalf("la période précédente s'arrête à %v", prev.To)
	}
	preReqs := GetTotals(d, prev).Requests
	if preReqs == 0 || cur.Requests == 0 {
		t.Fatal("le jeu de test doit avoir du trafic dans les deux périodes")
	}
	want := float64(cur.Requests-preReqs) / float64(preReqs) * 100
	if cur.RequestsDelta != want {
		t.Fatalf("delta = %v, attendu %v : la minute de frontière est comptée dans les deux périodes", cur.RequestsDelta, want)
	}
}

func TestBackendErrorsFromTheAggregates(t *testing.T) {
	d, base, lines := aggFixture(t)
	ctx := context.Background()
	d.Exec(`INSERT INTO proxies (id, name, config, enabled) VALUES ('p1','a','{"host":"a.fr","backend":"http://a:1"}',1)`)
	d.Exec(`INSERT INTO proxies (id, name, config, enabled) VALUES ('p2','b','{"host":"b.fr","backend":"http://b:2"}',1)`)
	for name, p := range map[string]Params{
		"tout":           {From: base, To: base.Add(2*time.Hour - time.Second)},
		"une passerelle": {From: base.Add(20 * time.Minute), To: base.Add(35*time.Minute - time.Second), NodeName: "edge-a"},
		"un domaine":     {From: base, To: base.Add(2*time.Hour - time.Second), Proxy: "b.fr"},
	} {
		got, err := GetBackendErrors(ctx, d, p)
		if err != nil || len(got) == 0 {
			t.Fatalf("%s : %v %v", name, got, err)
		}
		for _, r := range got {
			dom := Params{From: p.From, To: p.To, NodeName: p.NodeName, Proxy: r.Domain}
			w := expect(lines, dom, "2006-01-02")
			if r.Total != w.reqs || r.Errors != w.errs {
				t.Errorf("%s : %s %d requêtes %d erreurs, attendu %d / %d", name, r.Domain, r.Total, r.Errors, w.reqs, w.errs)
			}
			if r.AvgLatMs != float64(int64(float64(w.latSum)/float64(w.reqs)+0.5)) {
				t.Errorf("%s : %s latence %v, attendu %v", name, r.Domain, r.AvgLatMs, float64(w.latSum)/float64(w.reqs))
			}
		}
	}
}

// La liste des domaines d'une passerelle vient des cumuls par minute que celle-ci envoie.
func TestGetProxiesOfANodeComesFromTheMinuteAggregates(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	for _, r := range []struct{ node, domain string }{{"edge-a", "b.fr"}, {"edge-a", "a.fr"}, {"edge-a", ""}, {"edge-b", "c.fr"}} {
		if _, err := d.Exec(`INSERT INTO logs_minute (minute, node_name, domain, status, requests) VALUES ('2026-03-10T08:00', ?, ?, 200, 3)`, r.node, r.domain); err != nil {
			t.Fatal(err)
		}
	}
	got := GetProxies(d, "edge-a")
	if len(got) != 2 || got[0].Domain != "a.fr" || got[1].Domain != "b.fr" {
		t.Errorf("domaines de edge-a = %+v, attendu a.fr et b.fr", got)
	}
}
