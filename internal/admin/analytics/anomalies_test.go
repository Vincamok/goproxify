// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package analytics

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
)

func TestDetectAnomalies(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	now := time.Now().UTC()
	ins := func(at time.Time, domain, ip string, status, n int) {
		for i := 0; i < n; i++ {
			if _, err := d.Exec(`INSERT INTO logs (ts, domain, ip, status, latency_ms) VALUES (?,?,?,?,10)`,
				at.Format(time.RFC3339), domain, ip, status); err != nil {
				t.Fatal(err)
			}
		}
	}
	// 10 heures de trafic sain réparti sur des IPs variées, puis un pic d'erreurs 502 depuis une seule IP.
	for h := 10; h >= 1; h-- {
		at := now.Add(-time.Duration(h) * time.Hour)
		for k := 0; k < 8; k++ {
			ins(at, "api.acme.fr", "10.0.0."+string(rune('1'+k)), 200, 10)
		}
		ins(at, "api.acme.fr", "10.0.1.1", 500, 1)
	}
	ins(now.Add(-30*time.Minute), "api.acme.fr", "203.0.113.9", 502, 400)

	d.Exec(`INSERT INTO proxies (id, name, config, enabled) VALUES ('p1','api','{"host":"api.acme.fr","backend":"http://api:8080"}',1)`)
	d.Exec(`INSERT INTO geoip_cache (ip, country_code, country_name) VALUES ('203.0.113.9','CN','Chine')`)

	p := Params{From: now.Add(-12 * time.Hour), To: now}
	got := DetectAnomalies(context.Background(), d, p)

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

	// Période calme : rien à signaler.
	calm := DetectAnomalies(context.Background(), d, Params{From: now.Add(-11 * time.Hour), To: now.Add(-2 * time.Hour)})
	for _, a := range calm {
		if a.Kind == "error_spike" || a.Kind == "dominant_ip" {
			t.Errorf("aucune anomalie attendue sur la période calme, obtenu %+v", a)
		}
	}
}

// Une IP tronquée par l'anonymisation regroupe tout un /24 : Prism la garde dans le top IPs mais la
// marque, et l'anomalie « IP dominante » (action Bannir) vise la première IP attribuable.
func TestTruncatedIPsMarkedAndNeverDominant(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })

	at := time.Now().UTC().Add(-10 * time.Minute).Format(time.RFC3339)
	ins := func(ip string, truncated, n int) {
		for i := 0; i < n; i++ {
			if _, err := d.Exec(`INSERT INTO logs (ts, domain, ip, status, latency_ms, ip_truncated) VALUES (?,'api.acme.fr',?,200,10,?)`,
				at, ip, truncated); err != nil {
				t.Fatal(err)
			}
		}
	}
	ins("203.0.113.0", 1, 100)
	ins("2a01:e0a:1::", 1, 70)
	// Entrées pseudonymisées écrites avant Admin 0.71.1, sans marqueur.
	ins(logs.PseudonymizedIP, 0, 95)
	ins("198.51.100.7", 0, 90)
	ins("198.51.100.8", 0, 10)

	p := Params{From: time.Now().Add(-time.Hour), To: time.Now()}
	marked := map[string]bool{}
	for _, e := range GetTopIPs(d, p, 10) {
		marked[e.IP] = e.IPTruncated
	}
	want := map[string]bool{"203.0.113.0": true, "2a01:e0a:1::": true, logs.PseudonymizedIP: false, "198.51.100.7": false, "198.51.100.8": false}
	for ip, w := range want {
		if got, ok := marked[ip]; !ok || got != w {
			t.Errorf("GetTopIPs %s : présent=%v ip_truncated=%v, attendu présent, ip_truncated=%v", ip, ok, got, w)
		}
	}

	var dominant []Anomaly
	for _, a := range DetectAnomalies(context.Background(), d, p) {
		if a.Kind == "dominant_ip" {
			dominant = append(dominant, a)
		}
	}
	if len(dominant) != 1 || dominant[0].Subject != "198.51.100.7" {
		t.Fatalf("IP dominante = %+v, attendu 198.51.100.7 (IP tronquées et pseudonymisées écartées)", dominant)
	}
}
