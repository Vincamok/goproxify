// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
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
