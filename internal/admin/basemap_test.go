// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
)

func TestBasemapPath(t *testing.T) {
	t.Setenv("GPX_BASEMAP_PATH", "")
	if got := basemapPath(""); got != "" {
		t.Errorf("sans stockage ni variable : %q", got)
	}
	if got := basemapPath("/data"); got != filepath.Join("/data", "basemap", "basemap.pmtiles") {
		t.Errorf("défaut : %q", got)
	}
	t.Setenv("GPX_BASEMAP_PATH", "/maps/france.pmtiles")
	if got := basemapPath("/data"); got != "/maps/france.pmtiles" {
		t.Errorf("variable : %q", got)
	}
}

func TestBasemapHandlerServesRanges(t *testing.T) {
	file := filepath.Join(t.TempDir(), "basemap.pmtiles")
	if err := os.WriteFile(file, []byte("PMTiles0123456789"), 0o644); err != nil {
		t.Fatal(err)
	}
	h := basemapHandler(file)

	req := httptest.NewRequest(http.MethodGet, basemapRoute, nil)
	req.Header.Set("Range", "bytes=0-6")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusPartialContent || rec.Body.String() != "PMTiles" {
		t.Fatalf("Range : %d %q", rec.Code, rec.Body.String())
	}
	if rec.Header().Get("Content-Range") != "bytes 0-6/17" {
		t.Errorf("Content-Range : %q", rec.Header().Get("Content-Range"))
	}

	head := httptest.NewRecorder()
	h.ServeHTTP(head, httptest.NewRequest(http.MethodHead, basemapRoute, nil))
	if head.Code != http.StatusOK || head.Body.Len() != 0 {
		t.Errorf("HEAD : %d, corps %d octets", head.Code, head.Body.Len())
	}
}

func TestBasemapHandlerWithoutFile(t *testing.T) {
	for name, path := range map[string]string{"non défini": "", "absent": filepath.Join(t.TempDir(), "nope.pmtiles"), "dossier": t.TempDir()} {
		rec := httptest.NewRecorder()
		basemapHandler(path).ServeHTTP(rec, httptest.NewRequest(http.MethodGet, basemapRoute, nil))
		if rec.Code != http.StatusNotFound {
			t.Errorf("%s : %d, attendu 404", name, rec.Code)
		}
	}
}
