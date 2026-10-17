// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
	"github.com/vincamok/goproxify/internal/edge/waf"
)

// Le journal d'accès enveloppe les étapes de sécurité : sans support partagé, les catégories du WAF et le
// signal Sentinel posés sur la copie de la requête n'arrivaient jamais dans l'entrée (waf_matches toujours vide).
func TestAccessLog_RecordsWAFBlockAndSentinelSignal(t *testing.T) {
	al := edgelog.NewAccessLogger("")
	got := make(chan edgelog.ShipEntry, 4)
	al.SetForwarder(func(batch []edgelog.ShipEntry) {
		for _, e := range batch {
			got <- e
		}
	})
	engine := waf.NewEngine(nil, slog.Default())
	h := al.Middleware(engine.Middleware(&router.WAFConfig{Enabled: true, Mode: "block"}, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		threat.WithSignal(r, "threat: ua")
	})))

	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://app.test/?q=<script>alert(1)</script>", nil))
	if rr.Code != http.StatusForbidden {
		t.Fatalf("le WAF devait bloquer : %d", rr.Code)
	}
	rr = httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "http://app.test/", nil))

	var blocked, signalled edgelog.ShipEntry
	for range 2 {
		select {
		case e := <-got:
			if e.Status == http.StatusForbidden {
				blocked = e
			} else {
				signalled = e
			}
		case <-time.After(10 * time.Second):
			t.Fatal("entrées non expédiées")
		}
	}
	if !slices.Contains(blocked.WAFMatches, "xss") {
		t.Errorf("blocage WAF absent du journal : waf_matches=%v", blocked.WAFMatches)
	}
	if signalled.ThreatSignal != "threat: ua" {
		t.Errorf("signal Sentinel absent du journal : %q", signalled.ThreatSignal)
	}
}
