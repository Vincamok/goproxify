// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/prismedge"
	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/edge/logapi/logapitest"
	"github.com/vincamok/goproxify/internal/edge/waf/behavior"
)

func TestThreatReferencesAreReadFromEachGateway(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	paris, lyon := logapitest.New(t, "paris"), logapitest.New(t, "lyon")
	paris.References = logapi.EphorReferencesResponse{
		References: []behavior.RefInfo{{Route: "api.test", Hour: 10, Median: 4, Threshold: 20, Samples: 120, Ready: true}},
		Profiles:   42, ASN: logapi.ASNStatus{Version: "abc123def456", V4Ranges: 500000, V6Ranges: 90000}, TLSTable: behavior.TLSTableVersion,
	}
	lyon.References = logapi.EphorReferencesResponse{References: []behavior.RefInfo{}, TLSTable: behavior.TLSTableVersion}
	for _, g := range []*logapitest.Gateway{paris, lyon} {
		if err := g.Register(db); err != nil {
			t.Fatal(err)
		}
	}
	h := &SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}

	get := func(q string) map[string]any {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/threat-references"+q, nil))
		if rec.Code != http.StatusOK {
			t.Fatalf("%s : %d %s", q, rec.Code, rec.Body)
		}
		var out map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatal(err)
		}
		return out
	}

	all := get("")["gateways"].([]any)
	if len(all) != 2 {
		t.Fatalf("une entrée par passerelle : %v", all)
	}
	one := get("?edge=id-paris")["gateways"].([]any)
	if len(one) != 1 {
		t.Fatalf("edge=id-paris : %v", one)
	}
	gw := one[0].(map[string]any)
	refs := gw["references"].([]any)
	if gw["node_name"] != "paris" || len(refs) != 1 || refs[0].(map[string]any)["route"] != "api.test" || gw["profiles"].(float64) != 42 {
		t.Fatalf("passerelle de Paris : %v", gw)
	}
	if asn := gw["asn"].(map[string]any); asn["version"] != "abc123def456" {
		t.Fatalf("asn : %v", asn)
	}
	byName := get("?edge=lyon")["gateways"].([]any)
	if len(byName) != 1 || byName[0].(map[string]any)["node_name"] != "lyon" {
		t.Fatalf("edge=lyon : %v", byName)
	}
}

func TestThreatReferencesWithoutGateway(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	h := &SecurityHandler{DB: db, Edge: &prismedge.Source{DB: db}}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/security/threat-references", nil))
	if rec.Code == http.StatusOK {
		t.Fatalf("sans passerelle il n'y a rien à lire : %d %s", rec.Code, rec.Body)
	}
}
