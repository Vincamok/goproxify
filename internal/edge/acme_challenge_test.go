// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"net/http/httptest"
	"testing"

	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

func TestServeACMEChallenge(t *testing.T) {
	s := &Server{certStore: edgetls.NewCertStore()}
	s.certStore.Challenges.Apply(edgetls.ACMEChallenge{Type: edgetls.ChallengeHTTP01, Token: "tok", Response: "tok.thumb"}) //nolint:errcheck

	rec := httptest.NewRecorder()
	if !s.serveACMEChallenge(rec, httptest.NewRequest(http.MethodGet, "http://a.example.com/.well-known/acme-challenge/tok", nil)) {
		t.Fatal("token connu non servi")
	}
	if rec.Body.String() != "tok.thumb" || rec.Header().Get("Content-Type") != "text/plain" {
		t.Fatalf("réponse = %q (%s)", rec.Body.String(), rec.Header().Get("Content-Type"))
	}

	for _, path := range []string{"/.well-known/acme-challenge/inconnu", "/autre"} {
		if s.serveACMEChallenge(httptest.NewRecorder(), httptest.NewRequest(http.MethodGet, path, nil)) {
			t.Errorf("%s ne doit pas être intercepté", path)
		}
	}
	if s.serveACMEChallenge(httptest.NewRecorder(), httptest.NewRequest(http.MethodPost, "/.well-known/acme-challenge/tok", nil)) {
		t.Error("POST intercepté")
	}
}
