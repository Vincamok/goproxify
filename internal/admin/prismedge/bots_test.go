// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/analytics"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

// La part de robots de Prism filtré vient du compteur « bots » des passerelles ; ce compteur n'est calculé que sur
// demande, et seul FilteredTotals la fait : un Totals ordinaire (le miner du référentiel) ne paie pas ce calcul.
func TestFilteredTotalsAskForBotsAndPlainTotalsDoNot(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	gw := logapitest.New(t, "gw-a")
	if err := gw.Register(db); err != nil {
		t.Fatal(err)
	}
	at := time.Now().UTC().Add(-10 * time.Minute)
	for i := 0; i < 10; i++ {
		e := logstore.Entry{Ts: at.Add(time.Duration(i) * time.Second), Domain: "api.acme.fr", IP: "198.51.100.7", Path: "/p/1", Status: 200, UserAgent: "curl/8"}
		if i < 3 {
			e.UserAgent = "Googlebot/2.1"
		}
		gw.Add(e)
	}
	src := &Source{DB: db}
	p := analytics.Params{From: at.Add(-time.Hour), To: time.Now().UTC(), Path: "/p/1"}

	got, _, err := src.FilteredTotals(context.Background(), p)
	if err != nil {
		t.Fatal(err)
	}
	if got.Requests != 10 || got.Bots != 3 {
		t.Errorf("FilteredTotals : %d requêtes, %d robots, attendu 10 et 3", got.Requests, got.Bots)
	}

	it, found, _, err := src.Totals(context.Background(), p)
	if err != nil || !found {
		t.Fatalf("Totals : %v found=%v", err, found)
	}
	if it.Requests != 10 || it.Bots != 0 {
		t.Errorf("Totals : %d requêtes, %d robots, attendu 10 et 0 (compteur non demandé)", it.Requests, it.Bots)
	}
}
