// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func groupAttributesHandler(t *testing.T) *ArchitectureHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "a.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	store := archstore.New(t.TempDir())
	if err := store.Upsert(archstore.NodeEntry{ID: "e1", Role: "edge", Name: "lan-1",
		Config: json.RawMessage(`{"cluster":true,"cluster_group":"paris-lan"}`)}); err != nil {
		t.Fatal(err)
	}
	return &ArchitectureHandler{DB: db, Log: slog.Default(), Store: store}
}

func callGroupAttributes(h *ArchitectureHandler, method, path, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestGroupAttributesRoundTrip(t *testing.T) {
	h := groupAttributesHandler(t)
	const path = "/api/v1/architecture/groups/paris-lan/attributes"

	rec := callGroupAttributes(h, http.MethodGet, path, "")
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"tags":[]`) {
		t.Fatalf("lecture initiale : %d %s", rec.Code, rec.Body)
	}
	rec = callGroupAttributes(h, http.MethodPut, path, `{"environment":"prod","region":"paris","tags":["lan","interne"]}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("écriture : %d %s", rec.Code, rec.Body)
	}
	a := h.Store.GroupAttributesOf("paris-lan")
	if a.Environment != "prod" || a.Region != "paris" || len(a.Tags) != 2 {
		t.Fatalf("attributs retenus : %+v", a)
	}
	rec = callGroupAttributes(h, http.MethodGet, path, "")
	if !strings.Contains(rec.Body.String(), `"environment":"prod"`) {
		t.Fatalf("relecture : %s", rec.Body)
	}
}

func TestGroupAttributesRejectsUnknownGroupAndBadValues(t *testing.T) {
	h := groupAttributesHandler(t)
	if rec := callGroupAttributes(h, http.MethodPut, "/api/v1/architecture/groups/inconnu/attributes", `{}`); rec.Code != http.StatusNotFound {
		t.Fatalf("groupe inconnu : %d", rec.Code)
	}
	const path = "/api/v1/architecture/groups/paris-lan/attributes"
	for _, body := range []string{
		`{"environment":"pro d"}`,
		`{"tags":["a","A"]}`,
		`{"tags":[""]}`,
		`pas du json`,
	} {
		if rec := callGroupAttributes(h, http.MethodPut, path, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d", body, rec.Code)
		}
	}
	if a := h.Store.GroupAttributesOf("paris-lan"); a.Environment != "" {
		t.Fatalf("un refus ne doit rien retenir : %+v", a)
	}
}
