// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package monitor

import (
	"context"
	"log/slog"
	"path/filepath"
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
			if _, err := d.Exec(`INSERT INTO logs (ts, domain, ip, status) VALUES (?, 'a.fr', '1.1.1.1', 502)`,
				at.UTC().Format(time.RFC3339Nano)); err != nil {
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
		d.Exec(`INSERT INTO logs (ts, domain, node_name, ip, status) VALUES (?,?,?,?,?)`, at, "a.fr", "lyon-03", "1.1.1.1", status)
	}
	for _, e := range New(d, slog.Default(), nil, DefaultConfig()).sloEvents(context.Background()) {
		if e.NodeName == "lyon-03" {
			t.Fatalf("lyon-03 n'a pas de trafic depuis 7 h : pas d'évaluation par passerelle (fenêtre 6 h) : %+v", e)
		}
	}
}
