// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func TestGatewayCalibratesOnItsOwnAccessLogs(t *testing.T) {
	s := newLogGateway(t, t.TempDir(), "cle-calibrage")
	start := time.Now().UTC().Add(-90 * time.Minute)
	for i := 0; i < 600; i++ {
		s.logStore.Add(logstore.KindAccess, logstore.Entry{
			Ts: start.Add(time.Duration(i) * 5 * time.Second), Level: "info", Component: "edge", Domain: "api.example.com", Method: "GET",
			Path: fmt.Sprintf("/api/users/%d", i%7), Status: 200, Bytes: 10, LatencyMs: 5, IP: fmt.Sprintf("198.51.100.%d", i%20+1), UserAgent: "curl/8",
		})
	}
	s.logStore.Flush()

	call := func(body string) (int, logapi.EphorCalibrateResponse) {
		rec := httptest.NewRecorder()
		s.handleEphorCalibrate(rec, httptest.NewRequest(http.MethodPost, logapi.PathEphorCalibrate, strings.NewReader(body)))
		var out logapi.EphorCalibrateResponse
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return rec.Code, out
	}

	code, out := call(`{"hours":3,"min_hours":0.1}`)
	if code != http.StatusOK || out.Report.Events != 600 {
		t.Fatalf("les 600 accès sont rejoués : %d %+v", code, out.Report.Events)
	}
	if out.Report.Seasonal.Routes != 1 || len(out.Report.Seasonal.Candidates) == 0 {
		t.Fatalf("la route et la grille saisonnière : %+v", out.Report.Seasonal)
	}
	if len(out.Report.Enumeration.Candidates) == 0 {
		t.Fatalf("la passerelle fournit les gabarits : l'énumération est calibrée (%q)", out.Report.Enumeration.Note)
	}

	for name, body := range map[string]string{"fenêtre nulle": `{"hours":0}`, "fenêtre trop longue": `{"hours":9999}`, "min_hours négatif": `{"hours":2,"min_hours":-1}`, "JSON": `x`} {
		if code, _ := call(body); code != http.StatusBadRequest {
			t.Errorf("%s : %d, attendu 400", name, code)
		}
	}
}
