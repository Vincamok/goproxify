// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logstore"
)

func TestOTLPBodyFollowsTheJSONMapping(t *testing.T) {
	r := Record{Node: "gw-a", Kind: "access", Row: logstore.Row{ID: 42, Entry: logstore.Entry{
		Ts: time.Date(2026, 10, 21, 10, 0, 5, 123456000, time.UTC), Level: "warn", Component: "edge", Domain: "app.example.com",
		Method: "GET", Path: "/a", Status: 403, Bytes: 10, LatencyMs: 4, IP: "203.0.113.9", IPTruncated: true, WAFMatches: []string{"sqli", "xss"}, ThreatSignal: "scan"}}}
	sys := Record{Node: "gw-a", Kind: "system", Row: logstore.Row{ID: 7, Entry: logstore.Entry{Ts: r.Row.Ts, Level: "error", Component: "edge", Message: "panne"}}}

	var req struct {
		ResourceLogs []struct {
			Resource struct {
				Attributes []struct {
					Key   string
					Value map[string]any
				}
			}
			ScopeLogs []struct {
				Scope      struct{ Name string }
				LogRecords []struct {
					TimeUnixNano   string
					SeverityNumber int
					SeverityText   string
					Body           map[string]any
					Attributes     []struct {
						Key   string
						Value map[string]any
					}
				}
			}
		}
	}
	if err := json.Unmarshal(OTLPBody([]Record{r, sys}), &req); err != nil {
		t.Fatal(err)
	}
	if len(req.ResourceLogs) != 1 || len(req.ResourceLogs[0].ScopeLogs) != 1 {
		t.Fatalf("structure : %+v", req)
	}
	res := req.ResourceLogs[0].Resource.Attributes
	if res[0].Key != "service.name" || res[0].Value["stringValue"] != "goproxify-edge" || res[1].Key != "host.name" || res[1].Value["stringValue"] != "gw-a" {
		t.Errorf("ressource : %+v", res)
	}
	recs := req.ResourceLogs[0].ScopeLogs[0].LogRecords
	if len(recs) != 2 || recs[0].SeverityNumber != 13 || recs[0].SeverityText != "WARN" || recs[1].SeverityNumber != 17 {
		t.Fatalf("lignes : %+v", recs)
	}
	if recs[0].TimeUnixNano != "1792576805123456000" || recs[0].Body["stringValue"] != "GET /a 403" || recs[1].Body["stringValue"] != "panne" {
		t.Errorf("date ou corps : %+v / %+v", recs[0], recs[1])
	}
	attrs := map[string]map[string]any{}
	for _, a := range recs[0].Attributes {
		attrs[a.Key] = a.Value
	}
	// Un entier 64 bits s'écrit en chaîne, un booléen en booléen.
	if attrs["http.response.status_code"]["intValue"] != "403" || attrs["client.address"]["stringValue"] != "203.0.113.9" ||
		attrs["goproxify.client.ip_truncated"]["boolValue"] != true || attrs["goproxify.waf_matches"]["stringValue"] != "sqli,xss" ||
		attrs["log.id"]["stringValue"] != "gw-a:access:42" || attrs["server.address"]["stringValue"] != "app.example.com" {
		t.Errorf("attributs : %v", attrs)
	}
	for _, a := range recs[1].Attributes {
		if a.Key == "http.response.status_code" || a.Key == "http.response.body.size" {
			t.Errorf("attribut HTTP sur un log système : %s", a.Key)
		}
	}
}

func TestOTLPDestinationPostsJSONAndNeedsAnHTTPURL(t *testing.T) {
	var gotType, gotAuth string
	var body []byte
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotType, gotAuth = r.Header.Get("Content-Type"), r.Header.Get("Authorization")
		body, _ = io.ReadAll(r.Body)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte("{}"))
	}))
	defer srv.Close()
	d := Destination{ID: "o", Name: "Collector", Type: TypeOTLP, Address: srv.URL + "/v1/logs", Headers: map[string]string{"Authorization": "Bearer x"}}
	if err := (Config{Destinations: []Destination{d}}).Validate(); err != nil {
		t.Fatal(err)
	}
	s, err := NewSender(d)
	if err != nil {
		t.Fatal(err)
	}
	defer s.Close()
	if err := s.Send(context.Background(), records(2)); err != nil {
		t.Fatal(err)
	}
	if gotType != "application/json" || gotAuth != "Bearer x" || !strings.HasPrefix(string(body), `{"resourceLogs":[`) || !strings.Contains(string(body), `"log.id"`) {
		t.Errorf("requête : %s %s %.80s", gotType, gotAuth, body)
	}
	bad := Destination{ID: "o", Name: "x", Type: TypeOTLP, Address: "collector:4318"}
	if err := bad.Validate(); err == nil {
		t.Error("une adresse OTLP sans schéma est acceptée")
	}
	tls := Destination{ID: "o", Name: "x", Type: TypeOTLP, Address: "http://c/v1/logs", TLS: true}
	if err := tls.Validate(); err == nil {
		t.Error("tls sur OTLP est accepté (utiliser https)")
	}
}

func TestDestinationNodesAreValidated(t *testing.T) {
	ok := Destination{ID: "a", Name: "n", Type: TypeHTTP, Address: "http://h/", Nodes: []string{"gw-a", "gw-b"}}
	if err := ok.Validate(); err != nil {
		t.Fatal(err)
	}
	for name, nodes := range map[string][]string{"vide": {"gw-a", " "}, "trop long": {strings.Repeat("x", 129)}, "trop nombreux": make([]string, MaxNodes+1)} {
		for i := range nodes {
			if nodes[i] == "" {
				nodes[i] = "gw"
			}
		}
		d := ok
		d.Nodes = nodes
		if err := d.Validate(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
