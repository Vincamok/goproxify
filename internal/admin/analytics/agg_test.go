package analytics

import (
	"database/sql"
	"context"
	"path/filepath"
	"reflect"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

func aggFixture(t *testing.T) (*sql.DB, time.Time) {
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
	for i := 0; i < 600; i++ {
		ts := base.Add(time.Duration(i)*20*time.Second + 30*time.Second%time.Minute)
		d.Exec(`INSERT INTO logs (ts, component, node_name, domain, status, bytes, latency_ms) VALUES (?,?,?,?,?,?,?)`,
			ts.Format(time.RFC3339Nano), "edge", nodes[i%2], domains[i%3], statuses[i%len(statuses)], 100+i, 5+i%40)
	}
	// Lignes système (status 0) : jamais agrégées.
	d.Exec(`INSERT INTO logs (ts, component, status) VALUES (?, 'edge', 0)`, base.Add(time.Hour).Format(time.RFC3339Nano))
	return d, base
}



func TestAggregatesMatchRawLogs(t *testing.T) {
	d, base := aggFixture(t)
	ctx := context.Background()
	// Fenêtre de minutes entières (début à :00, fin à :59) : les agrégats arrondissent à la minute, les lignes brutes à la seconde.
	from, to := base, base.Add(2*time.Hour-time.Second)
	for _, p := range []Params{
		{From: from, To: to},
		{From: from, To: to, NodeName: "edge-a"},
		{From: from, To: to, Proxy: "a.fr"},
		{From: from, To: to, Proxy: "a.fr,b.fr", NodeName: "edge-b"},
	} {
		if aggUsable(ctx, d, p) {
			t.Fatal("agrégats utilisés avant le rattrapage")
		}
		rawK := GetKPIs(d, p, false)
		rawT := GetTimeline(d, p, "hour")
		rawS := GetStatusGroups(d, p)
		rawReq, rawErr := countReqErr(ctx, d, p)

		if err := logs.AggregateNow(ctx, d); err != nil {
			t.Fatal(err)
		}
		if !aggUsable(ctx, d, p) {
			t.Fatal("agrégats inutilisables après le rattrapage")
		}
		if got := GetKPIs(d, p, false); !reflect.DeepEqual(got, rawK) {
			t.Errorf("KPIs %+v : agrégats %+v, lignes brutes %+v", p, got, rawK)
		}
		if got := GetTimeline(d, p, "hour"); !reflect.DeepEqual(got, rawT) {
			t.Errorf("courbe %+v : agrégats %+v, lignes brutes %+v", p, got, rawT)
		}
		if got := GetStatusGroups(d, p); !reflect.DeepEqual(got, rawS) {
			t.Errorf("codes %+v : agrégats %+v, lignes brutes %+v", p, got, rawS)
		}
		if r, e := countReqErr(ctx, d, p); r != rawReq || e != rawErr {
			t.Errorf("SLO %+v : agrégats %d/%d, lignes brutes %d/%d", p, r, e, rawReq, rawErr)
		}
		d.Exec(`DELETE FROM logs_minute`)
		d.Exec(`DELETE FROM logs_minute_state`)
	}
}

func TestAggregationIsIncrementalAndNeverCountsTwice(t *testing.T) {
	d, base := aggFixture(t)
	ctx := context.Background()
	p := Params{From: base, To: base.Add(3 * time.Hour)}

	logs.AggregateNow(ctx, d)
	logs.AggregateNow(ctx, d)
	first, _ := countReqErr(ctx, d, p)

	d.Exec(`INSERT INTO logs (ts, component, node_name, domain, status, bytes, latency_ms) VALUES (?,?,?,?,?,?,?)`,
		base.Add(90*time.Minute).Format(time.RFC3339Nano), "edge", "edge-a", "a.fr", 500, 1, 1)
	logs.AggregateNow(ctx, d)
	logs.AggregateNow(ctx, d)
	second, errs2 := countReqErr(ctx, d, p)
	if second != first+1 {
		t.Fatalf("après une ligne de plus : %d, attendu %d", second, first+1)
	}
	if errs2 == 0 {
		t.Fatal("la ligne 500 doit compter comme erreur")
	}
}

func TestShortWindowsAndIPFiltersStayOnRawLogs(t *testing.T) {
	d, base := aggFixture(t)
	ctx := context.Background()
	logs.AggregateNow(ctx, d)
	if aggUsable(ctx, d, Params{From: base, To: base.Add(30 * time.Minute)}) {
		t.Fatal("fenêtre de 30 min servie par les agrégats")
	}
	if aggUsable(ctx, d, Params{From: base, To: base.Add(2 * time.Hour), IP: "1.2.3.4"}) {
		t.Fatal("filtre IP servi par les agrégats")
	}
	if aggUsable(ctx, d, Params{From: base, To: base.Add(2 * time.Hour), Path: "/x"}) {
		t.Fatal("filtre chemin servi par les agrégats")
	}
}
