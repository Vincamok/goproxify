// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// La doc (rgpd.md, aide de reveal-ip) écrit les options en --x : parseFlags les rangeait sous
// « --x », que flagValue(args, "-x") ne trouvait pas.
func TestParseFlagsAcceptsDoubleDash(t *testing.T) {
	m := parseFlags([]string{"--entry-id", "42", "-reason", "Art. 17", "--dry"})
	if m["-entry-id"] != "42" || m["-reason"] != "Art. 17" {
		t.Fatalf("parseFlags = %v", m)
	}
	if _, ok := m["-dry"]; !ok {
		t.Fatalf("--dry sans valeur absent : %v", m)
	}
}

func TestLogsDeleteCallsTheErasureRoute(t *testing.T) {
	var method, path, reason string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		var body struct{ Reason string }
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		reason = body.Reason
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"deleted":3}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "logs", "delete", "--by-ip", "2001:db8::1", "--reason", "Art. 17", "-admin-url", srv.URL, "-token", "t"}
	runLogs()

	if method != http.MethodDelete || path != "/api/v1/logs/by-ip/2001:db8::1" || reason != "Art. 17" {
		t.Fatalf("requête %s %s reason=%q", method, path, reason)
	}
}

func TestLogsSubjectExportPostsTheSubjectInTheBody(t *testing.T) {
	var method, path, ip, user, reason string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		method, path = r.Method, r.URL.Path
		var body struct{ IP, UserID, Reason string }
		json.NewDecoder(r.Body).Decode(&body) //nolint:errcheck
		ip, user, reason = body.IP, body.UserID, body.Reason
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"203.0.113.42"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	out := filepath.Join(t.TempDir(), "export.json")
	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "logs", "subject-export", "--by-ip", "203.0.113.42", "--reason", "Art. 15", "--output", out, "-admin-url", srv.URL, "-token", "t"}
	runLogs()

	if method != http.MethodPost || path != "/api/v1/logs/subject-export" || ip != "203.0.113.42" || user != "" || reason != "Art. 15" {
		t.Fatalf("requête %s %s ip=%q user=%q reason=%q (l'IP doit voyager dans le corps, pas dans l'URL)", method, path, ip, user, reason)
	}
	if b, err := os.ReadFile(out); err != nil || !strings.Contains(string(b), "203.0.113.42") {
		t.Fatalf("fichier d'export : %q, %v", b, err)
	}
}
