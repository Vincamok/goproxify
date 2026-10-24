// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"database/sql"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

// fakeRemote est la source des règles qui portent sur des lignes : ce que les passerelles répondraient.
type fakeRemote struct {
	ip  IPEntry
	geo []GeoEntry
}

func (f fakeRemote) Available(context.Context, Params) bool { return true }
func (f fakeRemote) TopAttributableIP(context.Context, Params) (IPEntry, bool, error) {
	return f.ip, f.ip.IP != "", nil
}
func (f fakeRemote) GeoBreakdown(context.Context, Params) ([]GeoEntry, error) { return f.geo, nil }
func (f fakeRemote) FilteredTimeline(context.Context, Params, string) ([]TimePoint, error) {
	return nil, nil
}
func (f fakeRemote) FilteredTotals(context.Context, Params) (Totals, error) { return Totals{}, nil }

func anomalyDB(t *testing.T) *sql.DB {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return d
}

func TestDetectAnomalies(t *testing.T) {
	d := anomalyDB(t)
	now := time.Now().UTC()
	ins := func(at time.Time, status, n int) {
		if _, err := d.Exec(`INSERT INTO logs_minute (minute, node_name, domain, status, requests, latency_ms_sum) VALUES (?, 'edge-a', 'api.acme.fr', ?, ?, ?)
			ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + excluded.requests`,
			at.Format("2006-01-02T15:04"), status, n, n*10); err != nil {
			t.Fatal(err)
		}
	}
	// 10 heures de trafic sain, puis un pic d'erreurs 502.
	for h := 10; h >= 1; h-- {
		at := now.Add(-time.Duration(h) * time.Hour)
		ins(at, 200, 80)
		ins(at, 500, 1)
	}
	ins(now.Add(-30*time.Minute), 502, 400)

	d.Exec(`INSERT INTO proxies (id, name, config, enabled) VALUES ('p1','api','{"host":"api.acme.fr","backend":"http://api:8080"}',1)`)
	remote := fakeRemote{ip: IPEntry{IP: "203.0.113.9", Requests: 400, Errors: 400},
		geo: []GeoEntry{{CountryCode: "CN", CountryName: "Chine", Requests: 400, Errors: 400, ErrorRate: 100}, {CountryCode: "FR", CountryName: "France", Requests: 800, Errors: 10, ErrorRate: 1.25}}}

	p := Params{From: now.Add(-12 * time.Hour), To: now}
	got := DetectAnomalies(context.Background(), d, p, remote)

	kinds := map[string]Anomaly{}
	for _, a := range got {
		kinds[a.Kind] = a
	}
	for _, k := range []string{"error_spike", "dominant_ip", "country_errors", "backend_errors"} {
		if _, ok := kinds[k]; !ok {
			t.Errorf("anomalie %q attendue, obtenu %+v", k, got)
		}
	}
	if a := kinds["dominant_ip"]; a.Subject != "203.0.113.9" || a.Banned {
		t.Errorf("IP dominante inattendue : %+v", a)
	}
	if a := kinds["country_errors"]; a.Subject != "CN" {
		t.Errorf("pays inattendu : %+v", a)
	}
	if got[0].Level != "critical" {
		t.Errorf("les anomalies critiques doivent passer en premier : %+v", got)
	}

	// Sans passerelle, les règles qui portent sur des lignes ne sont pas évaluées ; les autres le sont.
	for _, a := range DetectAnomalies(context.Background(), d, p, nil) {
		if a.Kind == "dominant_ip" || a.Kind == "country_errors" {
			t.Errorf("règle sur des lignes évaluée sans passerelle : %+v", a)
		}
	}

	// Période calme : rien à signaler.
	calm := DetectAnomalies(context.Background(), d, Params{From: now.Add(-11 * time.Hour), To: now.Add(-2 * time.Hour)}, fakeRemote{})
	for _, a := range calm {
		if a.Kind == "error_spike" || a.Kind == "dominant_ip" {
			t.Errorf("aucune anomalie attendue sur la période calme, obtenu %+v", a)
		}
	}
}
