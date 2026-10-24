// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"io"
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

// captureStderr exécute fn et rend ce qu'elle a écrit sur la sortie d'erreur.
func captureStderr(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stderr
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stderr = w
	done := make(chan string)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stderr = old
	return <-done
}

func TestLogsListAsksTheGatewaysAndExplainsIncompleteResults(t *testing.T) {
	var query string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		query = r.URL.RawQuery
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"source":"edge","has_more":true,"cursor":"PAGE2","partial":true,` + //nolint:errcheck
			`"unreachable":[{"node_id":"n-b","node_name":"gw-b","error":"refusée"}],` +
			`"entries":[{"ts":"2026-10-21T10:00:09.000000Z","level":"info","status":200,"domain":"app.example.com","method":"GET","path":"/x","ip":"198.51.100.1"}]}`))
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "logs", "list", "-source", "edge", "-node", "gw-a", "-limit", "25", "-cursor", "PAGE1", "-from", "2026-10-21T00:00:00Z", "-admin-url", srv.URL, "-token", "t"}
	var stderr string
	stdout := captureStdout(t, func() { stderr = captureStderr(t, runLogs) })

	for _, want := range []string{"source=edge", "node_name=gw-a", "page_size=25", "cursor=PAGE1", "date_from="} {
		if !strings.Contains(query, want) {
			t.Errorf("la requête %q doit contenir %q", query, want)
		}
	}
	if !strings.Contains(stdout, "2026-10-21T10:00:09") || !strings.Contains(stdout, "/x") {
		t.Errorf("la ligne n'est pas affichée (horodatage `ts` lu ?) : %q", stdout)
	}
	for _, want := range []string{"injoignable(s) : gw-b", "Recherche partielle", "-cursor PAGE2"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("la sortie d'erreur doit mentionner %q : %q", want, stderr)
		}
	}
}

func TestLogsRevealIPAcceptsAGatewayLineReference(t *testing.T) {
	var body map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&body)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ip":"203.0.113.42","requested_by":"u1","ts":"now"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "logs", "reveal-ip", "--entry-ref", "n-a:access:42", "--reason", "Art. 15", "-admin-url", srv.URL, "-token", "t"}
	out := captureStdout(t, runLogs)
	if body["entry_ref"] != "n-a:access:42" || body["reason"] != "Art. 15" || body["entry_id"] != nil {
		t.Fatalf("corps = %v", body)
	}
	if !strings.Contains(out, "203.0.113.42") {
		t.Fatalf("IP non affichée : %q", out)
	}
}

func TestLogsQueryKeyMapsTheCLIOptions(t *testing.T) {
	for flag, want := range map[string]string{
		"-from": "date_from", "-to": "date_to", "-limit": "page_size", "-node": "node_name", "-tls-ja4": "tls_ja4",
		"-source": "source", "-cursor": "cursor", "-domain": "domain",
	} {
		if got := logsQueryKey(flag); got != want {
			t.Errorf("%s → %s, attendu %s", flag, got, want)
		}
	}
}

// captureStdout exécute fn et rend ce qu'elle a écrit sur la sortie standard.
func captureStdout(t *testing.T, fn func()) string {
	t.Helper()
	old := os.Stdout
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatal(err)
	}
	os.Stdout = w
	done := make(chan string)
	go func() {
		var sb strings.Builder
		buf := make([]byte, 4096)
		for {
			n, err := r.Read(buf)
			sb.Write(buf[:n])
			if err != nil {
				break
			}
		}
		done <- sb.String()
	}()
	fn()
	w.Close()
	os.Stdout = old
	return <-done
}

func TestLogsSIEMSetShowAndDisable(t *testing.T) {
	var puts []string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch {
		case r.URL.Path == "/api/v1/logs/siem" && r.Method == http.MethodPut:
			b, _ := io.ReadAll(r.Body)
			puts = append(puts, string(b))
			w.Write([]byte(`{"enabled":true,"destinations":[{"name":"Splunk"}]}`)) //nolint:errcheck
		case r.URL.Path == "/api/v1/logs/siem":
			w.Write([]byte(`{"enabled":true,"destinations":[{"name":"Splunk","headers":{"Authorization":"********"}}]}`)) //nolint:errcheck
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	saved := os.Args
	defer func() { os.Args = saved }()

	file := filepath.Join(t.TempDir(), "siem.json")
	if err := os.WriteFile(file, []byte(`{"enabled":true,"destinations":[{"name":"Splunk","type":"http","address":"https://s.example/in"}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	os.Args = []string{"goproxify", "logs", "siem", "set", "--file", file, "-admin-url", srv.URL, "-token", "t"}
	runLogs()
	if len(puts) != 1 || !strings.Contains(puts[0], `"address":"https://s.example/in"`) {
		t.Fatalf("PUT du fichier : %v", puts)
	}

	// « disable » relit la configuration masquée et la renvoie telle quelle avec enabled=false : les jetons restent.
	os.Args = []string{"goproxify", "logs", "siem", "disable", "-admin-url", srv.URL, "-token", "t"}
	runLogs()
	if len(puts) != 2 || !strings.Contains(puts[1], `"enabled":false`) || !strings.Contains(puts[1], `"Authorization":"********"`) {
		t.Fatalf("PUT de disable : %v", puts)
	}
}
