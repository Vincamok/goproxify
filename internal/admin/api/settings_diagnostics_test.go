// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func newDiagnosticsHandler(t *testing.T) *DiagnosticsSettingsHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "d.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return NewDiagnosticsSettingsHandler(db, slog.Default())
}

func diagCall(h *DiagnosticsSettingsHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestDiagnostics_ProfilingIsOffUntilEnabled(t *testing.T) {
	h := newDiagnosticsHandler(t)

	rec := diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics", "")
	var st struct {
		ProfilingEnabled bool         `json:"profiling_enabled"`
		Runtime          runtimeStats `json:"runtime"`
	}
	if rec.Code != http.StatusOK || json.Unmarshal(rec.Body.Bytes(), &st) != nil {
		t.Fatalf("GET : %d %s", rec.Code, rec.Body.String())
	}
	if st.ProfilingEnabled {
		t.Error("profilage actif par défaut")
	}
	if st.Runtime.Goroutines == 0 || st.Runtime.HeapInuseBytes == 0 || st.Runtime.GoVersion == "" {
		t.Errorf("état du runtime vide : %+v", st.Runtime)
	}

	if rec := diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=heap", ""); rec.Code != http.StatusForbidden {
		t.Fatalf("profil sans activation : %d, attendu 403", rec.Code)
	}

	if rec := diagCall(h, http.MethodPut, "/api/v1/settings/diagnostics", `{"profiling_enabled":true}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body.String())
	}
	rec = diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=heap&format=text", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), "heap profile") {
		t.Fatalf("profil du tas : %d %.200s", rec.Code, rec.Body.String())
	}
	rec = diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=goroutine", "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Header().Get("Content-Disposition"), "goproxify-admin-goroutine.pb.gz") {
		t.Fatalf("profil goroutine : %d %v", rec.Code, rec.Header())
	}

	if rec := diagCall(h, http.MethodPut, "/api/v1/settings/diagnostics", `{"profiling_enabled":false}`); rec.Code != http.StatusOK {
		t.Fatalf("PUT off : %d", rec.Code)
	}
	if rec := diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=heap", ""); rec.Code != http.StatusForbidden {
		t.Errorf("profil après désactivation : %d, attendu 403", rec.Code)
	}
}

func TestDiagnostics_RejectsBadRequests(t *testing.T) {
	h := newDiagnosticsHandler(t)
	for _, c := range []struct {
		method, path, body string
		want               int
	}{
		{http.MethodPut, "/api/v1/settings/diagnostics", `{}`, http.StatusBadRequest},
		{http.MethodPut, "/api/v1/settings/diagnostics", `pas du json`, http.StatusBadRequest},
		{http.MethodPost, "/api/v1/settings/diagnostics", `{}`, http.StatusNotFound},
		{http.MethodGet, "/api/v1/settings/diagnostics/inconnu", "", http.StatusNotFound},
	} {
		if rec := diagCall(h, c.method, c.path, c.body); rec.Code != c.want {
			t.Errorf("%s %s : %d, attendu %d", c.method, c.path, rec.Code, c.want)
		}
	}
	diagCall(h, http.MethodPut, "/api/v1/settings/diagnostics", `{"profiling_enabled":true}`)
	if rec := diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=nimporte", ""); rec.Code != http.StatusBadRequest {
		t.Errorf("type inconnu : %d, attendu 400", rec.Code)
	}
}

// Une passerelle devant l'Admin coupe une réponse dont les en-têtes tardent plus de 30 s : ils doivent partir au
// début de la capture, pas à sa fin.
func TestDiagnostics_CPUProfileSendsHeadersBeforeTheCaptureEnds(t *testing.T) {
	h := newDiagnosticsHandler(t)
	diagCall(h, http.MethodPut, "/api/v1/settings/diagnostics", `{"profiling_enabled":true}`)
	srv := httptest.NewServer(h)
	defer srv.Close()

	start := time.Now()
	resp, err := http.Get(srv.URL + "/api/v1/settings/diagnostics/profile?type=cpu&seconds=3")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if wait := time.Since(start); wait > time.Second {
		t.Errorf("en-têtes reçus après %v : ils attendent la fin de la capture", wait)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil || len(body) < 2 || body[0] != 0x1f || body[1] != 0x8b {
		t.Fatalf("profil illisible : %v, %d octets", err, len(body))
	}
	if total := time.Since(start); total < 2*time.Second {
		t.Errorf("capture de %v, attendu ~3 s", total)
	}
}

func TestDiagnostics_CPUProfile(t *testing.T) {
	h := newDiagnosticsHandler(t)
	diagCall(h, http.MethodPut, "/api/v1/settings/diagnostics", `{"profiling_enabled":true}`)
	rec := diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=cpu&seconds=1", "")
	if rec.Code != http.StatusOK || rec.Body.Len() == 0 {
		t.Fatalf("profil CPU : %d, %d octets", rec.Code, rec.Body.Len())
	}
	// gzip : 0x1f 0x8b
	if b := rec.Body.Bytes(); b[0] != 0x1f || b[1] != 0x8b {
		t.Errorf("le profil n'est pas un pprof compressé : % x", b[:2])
	}

	h.cpuBusy.Store(true)
	if rec := diagCall(h, http.MethodGet, "/api/v1/settings/diagnostics/profile?type=cpu&seconds=1", ""); rec.Code != http.StatusConflict {
		t.Errorf("deux profils CPU simultanés : %d, attendu 409", rec.Code)
	}
}
