// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestAccessEventsOnlyCountTheObservationWindow(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ins := func(at time.Time, n int) {
		for i := 0; i < n; i++ {
			if _, err := d.Exec(`INSERT INTO logs_minute (minute, domain, node_name, status, requests) VALUES (?, 'a.fr', '', 502, 1) ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + 1, latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum`,
				at.UTC().Format("2006-01-02T15:04")); err != nil {
				t.Fatal(err)
			}
		}
	}
	m := New(d, slog.Default(), nil, Config{ErrorRatePct: 10, WindowSec: 300})

	ins(time.Now().Add(-20*time.Minute), 20)
	if evs := m.accessEvents(context.Background()); len(evs) != 0 {
		t.Fatalf("des erreurs vieilles de 20 min sont hors d'une fenêtre de 5 min : %+v", evs)
	}
	ins(time.Now().Add(-time.Minute), 10)
	evs := m.accessEvents(context.Background())
	if len(evs) != 1 || evs[0].Trigger != alerting.TriggerHighErrorRate || evs[0].Detail["total"] != int64(10) {
		t.Fatalf("une alerte taux d'erreur sur les 10 requêtes de la fenêtre attendue : %+v", evs)
	}
}

func TestSLOEventsSkipNodesWithoutRecentTraffic(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	at := time.Now().Add(-7 * time.Hour).UTC().Format(time.RFC3339)
	for i := 0; i < 100; i++ {
		status := 200
		if i < 20 {
			status = 502
		}
		d.Exec(`INSERT INTO logs_minute (minute, domain, node_name, status, requests) VALUES (?,?,?,?,1) ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + 1, latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum`, at[:16], "a.fr", "lyon-03", status)
	}
	for _, e := range New(d, slog.Default(), nil, DefaultConfig()).sloEvents(context.Background()) {
		if e.NodeName == "lyon-03" {
			t.Fatalf("lyon-03 n'a pas de trafic depuis 7 h : pas d'évaluation par passerelle (fenêtre 6 h) : %+v", e)
		}
	}
}

// Les alertes par domaine et la présence des passerelles sont lues dans les cumuls par minute que celles-ci envoient :
// mêmes domaines, mêmes chiffres, fenêtre d'observation respectée.
func TestAccessEventsFromTheMinuteAggregates(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	ins := func(at time.Time, domain string, status, n int) {
		if _, err := d.Exec(`INSERT INTO logs_minute (minute, domain, node_name, status, requests, latency_ms_sum) VALUES (?, ?, 'gw-a', ?, ?, ?)
			ON CONFLICT (minute, node_name, domain, status) DO UPDATE SET requests = requests + excluded.requests, latency_ms_sum = latency_ms_sum + excluded.latency_ms_sum`,
			at.UTC().Format("2006-01-02T15:04"), domain, status, n, 40*n); err != nil {
			t.Fatal(err)
		}
	}
	// a.fr : 60 % d'erreurs dans la fenêtre ; b.fr : sain ; c.fr : trop peu de requêtes ; d.fr : erreurs trop vieilles.
	ins(time.Now().Add(-90*time.Second), "a.fr", 502, 12)
	ins(time.Now().Add(-90*time.Second), "a.fr", 200, 8)
	ins(time.Now().Add(-90*time.Second), "b.fr", 200, 30)
	ins(time.Now().Add(-90*time.Second), "c.fr", 502, 5)
	ins(time.Now().Add(-30*time.Minute), "d.fr", 502, 40)
	m := New(d, slog.Default(), nil, Config{ErrorRatePct: 10, LatencyMsP95: 20, WindowSec: 300})

	got := map[string]string{}
	for _, e := range m.accessEvents(context.Background()) {
		got[e.Domain+"/"+string(e.Trigger)] = fmt.Sprint(e.Detail["total"], e.Detail["errors"], e.Detail["avg_lat_ms"])
	}
	if len(got) != 3 || got["a.fr/"+string(alerting.TriggerHighErrorRate)] != fmt.Sprint(int64(20), int64(12), nil) {
		t.Fatalf("alertes = %v, attendu le taux d'erreur de a.fr (20 requêtes, 12 erreurs) et la latence de a.fr et b.fr", got)
	}
	for _, domain := range []string{"c.fr", "d.fr"} {
		for k := range got {
			if strings.HasPrefix(k, domain+"/") {
				t.Errorf("alerte inattendue pour %s : %s", domain, k)
			}
		}
	}

	rows, err := m.activeNodes(context.Background(), 6*time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var nodes []string
	for rows.Next() {
		var n string
		_ = rows.Scan(&n)
		nodes = append(nodes, n)
	}
	if len(nodes) != 1 || nodes[0] != "gw-a" {
		t.Fatalf("passerelles actives = %v", nodes)
	}
}
