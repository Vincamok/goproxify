// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package attackref

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
)

// Le total de requêtes du miner se lit dans les cumuls par minute de l'Admin, sans interroger les passerelles.
func TestTotalRequestsReadsTheMinuteAggregates(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	now := time.Now().UTC()
	rows := []struct {
		at   time.Time
		node string
		n    int64
	}{
		{now.Add(-48 * time.Hour), "gw-a", 100},
		{now.Add(-48 * time.Hour), "gw-b", 50},
		{now.Add(-2 * time.Hour), "gw-a", 7},
		{now.Add(-40 * 24 * time.Hour), "gw-a", 9999},
	}
	for _, r := range rows {
		if _, err := db.Exec(`INSERT INTO logs_minute (minute, node_name, domain, status, requests) VALUES (?, ?, 'a.example.com', 200, ?)`,
			logs.MinuteKey(r.at), r.node, r.n); err != nil {
			t.Fatal(err)
		}
	}
	tr := EdgeTraffic{Source: &prismedge.Source{DB: db}}

	got, err := tr.TotalRequests(context.Background(), now.Add(-30*24*time.Hour), now)
	if err != nil {
		t.Fatal(err)
	}
	if got != 157 {
		t.Errorf("total sur 30 jours = %d, attendu 157 (la minute d'il y a 40 jours est hors période)", got)
	}
}
