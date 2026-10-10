// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/plugins"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
	"github.com/vincamok/goproxify/internal/edge/router"
)

type bodyReply struct {
	code        int
	body        string
	header      http.Header
	backendBody string
	backendCL   string
	called      bool
}

// bodyRequest envoie une requête avec corps à travers la chaîne d'une route portant les plugins donnés. Le backend
// répond avec respBody (et respHeaders) et enregistre ce qu'il a reçu.
func bodyRequest(t *testing.T, s *Server, method, reqBody, respBody string, respHeaders map[string]string, refs ...router.PluginRef) bodyReply {
	t.Helper()
	var got bodyReply
	backend := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		got.called = true
		b, _ := io.ReadAll(r.Body)
		got.backendBody, got.backendCL = string(b), r.Header.Get("Content-Length")
		for k, v := range respHeaders {
			w.Header().Set(k, v)
		}
		if respBody != "" {
			_, _ = io.WriteString(w, respBody)
		}
	}))
	defer backend.Close()
	route := &router.Route{ID: "body-" + strconv.Itoa(nextPluginReq()), Host: "app.test", Type: router.RouteHTTP, Backends: []router.Backend{{URL: backend.URL}}, Plugins: refs}
	var in io.Reader
	if reqBody != "" {
		in = strings.NewReader(reqBody)
	}
	req := httptest.NewRequest(method, "http://app.test/x", in)
	req.RemoteAddr = "203.0.113.9:1234"
	rr := httptest.NewRecorder()
	s.handlerForRoute(route, "").ServeHTTP(rr, req)
	got.code, got.body, got.header = rr.Code, rr.Body.String(), rr.Header()
	return got
}

func installBody(t *testing.T, s *Server, name, output string, hooks []string, mutate func(*plugins.Manifest)) {
	t.Helper()
	m := plugins.Manifest{Name: name, Version: "1", APIVersion: 1, Hooks: hooks}
	if mutate != nil {
		mutate(&m)
	}
	wasm := pt.Static(output)
	if err := s.ensurePluginManager().Install(t.Context(), packageOf(m, wasm)); err != nil {
		t.Fatal(err)
	}
}

func TestPluginBody_RequestDenyReplaceAndOversize(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	installBody(t, s, "deny-body", `{"action":"deny","status":400,"body":"corps refusé"}`, []string{"request_body"}, nil)
	installBody(t, s, "replace-body", `{"action":"modify","replace_body":"aGVsbG8=","set_headers":{"X-Rewritten":"1"}}`, []string{"request_body"}, nil)
	installBody(t, s, "small-deny", `{"action":"modify"}`, []string{"request_body"}, func(m *plugins.Manifest) { m.Limits.MaxBodyBytes = 8 })
	installBody(t, s, "small-skip", `{"action":"deny","status":400}`, []string{"request_body"}, func(m *plugins.Manifest) { m.Limits.MaxBodyBytes = 8; m.OnOversize = "skip" })

	r := bodyRequest(t, s, "POST", "données", "", nil, router.PluginRef{Name: "deny-body"})
	if r.code != 400 || r.body != "corps refusé" || r.called {
		t.Errorf("refus : %d %q backend appelé=%v", r.code, r.body, r.called)
	}
	r = bodyRequest(t, s, "POST", "corps d'origine", "", nil, router.PluginRef{Name: "replace-body"})
	if r.code != 200 || r.backendBody != "hello" || r.backendCL != "5" {
		t.Errorf("remplacement : %d, backend a reçu %q (CL %q)", r.code, r.backendBody, r.backendCL)
	}
	// Corps plus gros que la limite : refus 413 (deny), ou passage intact sans examen (skip).
	big := strings.Repeat("x", 100)
	r = bodyRequest(t, s, "POST", big, "", nil, router.PluginRef{Name: "small-deny"})
	if r.code != http.StatusRequestEntityTooLarge || r.called {
		t.Errorf("dépassement deny : %d appelé=%v", r.code, r.called)
	}
	r = bodyRequest(t, s, "POST", big, "", nil, router.PluginRef{Name: "small-skip"})
	if r.code != 200 || r.backendBody != big {
		t.Errorf("dépassement skip : %d, le backend doit recevoir les %d octets (reçu %d)", r.code, len(big), len(r.backendBody))
	}
	// Sans corps, le hook n'est pas appelé (le plugin refuserait sinon).
	if r := bodyRequest(t, s, "GET", "", "", nil, router.PluginRef{Name: "deny-body"}); r.code != 200 {
		t.Errorf("requête sans corps : %d", r.code)
	}
}

func TestPluginBody_ResponseReplaceDenyAndOversize(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	installBody(t, s, "resp-replace", `{"action":"modify","replace_body":"cmVkYWN0ZWQ=","set_headers":{"X-Filtered":"yes"}}`, []string{"response_body"}, nil)
	installBody(t, s, "resp-deny", `{"action":"deny","status":502,"body":"filtré"}`, []string{"response_body"}, nil)
	installBody(t, s, "resp-small-deny", `{"action":"modify"}`, []string{"response_body"}, func(m *plugins.Manifest) { m.Limits.MaxBodyBytes = 8 })
	installBody(t, s, "resp-small-skip", `{"action":"deny","status":502}`, []string{"response_body"}, func(m *plugins.Manifest) { m.Limits.MaxBodyBytes = 8; m.OnOversize = "skip" })

	r := bodyRequest(t, s, "GET", "", "secret=42", nil, router.PluginRef{Name: "resp-replace"})
	if r.code != 200 || r.body != "redacted" || r.header.Get("X-Filtered") != "yes" || r.header.Get("Content-Length") != "8" {
		t.Errorf("remplacement : %d %q %v", r.code, r.body, r.header)
	}
	// Le refus remplace tout, y compris les en-têtes propres à la réponse du backend (cookie, codage).
	r = bodyRequest(t, s, "GET", "", "contenu", map[string]string{"Set-Cookie": "sid=1", "Content-Encoding": "gzip", "ETag": `"abc"`}, router.PluginRef{Name: "resp-deny"})
	if r.code != 502 || r.body != "filtré" || r.header.Get("Set-Cookie") != "" || r.header.Get("Content-Encoding") != "" || r.header.Get("ETag") != "" {
		t.Errorf("refus : %d %q %v", r.code, r.body, r.header)
	}
	long := strings.Repeat("y", 100)
	r = bodyRequest(t, s, "GET", "", long, nil, router.PluginRef{Name: "resp-small-deny"})
	if r.code != http.StatusBadGateway || strings.Contains(r.body, "yyy") {
		t.Errorf("dépassement deny : %d %q", r.code, r.body)
	}
	r = bodyRequest(t, s, "GET", "", long, nil, router.PluginRef{Name: "resp-small-skip"})
	if r.code != 200 || r.body != long {
		t.Errorf("dépassement skip : %d, %d octets reçus", r.code, len(r.body))
	}
	// Un flux (SSE) ne peut pas être retenu : traité comme un dépassement.
	r = bodyRequest(t, s, "GET", "", "data: x\n\n", map[string]string{"Content-Type": "text/event-stream"}, router.PluginRef{Name: "resp-small-deny"})
	if r.code != http.StatusBadGateway {
		t.Errorf("flux avec politique deny : %d", r.code)
	}
	r = bodyRequest(t, s, "GET", "", "data: x\n\n", map[string]string{"Content-Type": "text/event-stream"}, router.PluginRef{Name: "resp-small-skip"})
	if r.code != 200 || r.body != "data: x\n\n" {
		t.Errorf("flux avec politique skip : %d %q", r.code, r.body)
	}
	// HEAD n'a pas de corps : rien à examiner, la réponse passe.
	if r := bodyRequest(t, s, "HEAD", "", "", nil, router.PluginRef{Name: "resp-deny"}); r.code != 200 {
		t.Errorf("HEAD : %d", r.code)
	}
	// Une réponse vide est examinée comme les autres.
	if r := bodyRequest(t, s, "GET", "", "", nil, router.PluginRef{Name: "resp-deny"}); r.code != 502 {
		t.Errorf("réponse vide : %d (le plugin doit la voir)", r.code)
	}
}
