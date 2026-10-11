// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func readAll(h http.Handler, path, body string) (int, error) {
	var n int
	var err error
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(body))
	req.ContentLength = -1 // corps en flux : pas d'en-tête Content-Length pour annoncer la taille
	limitRequestBodies(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		var b []byte
		b, err = io.ReadAll(r.Body)
		n = len(b)
	})).ServeHTTP(rec, req)
	_ = h
	return n, err
}

func TestLimitRequestBodies(t *testing.T) {
	if _, err := readAll(nil, "/api/v1/auth/login", strings.Repeat("x", maxPublicBody)); err != nil {
		t.Errorf("un corps à la limite publique doit passer : %v", err)
	}
	if _, err := readAll(nil, "/api/v1/auth/login", strings.Repeat("x", maxPublicBody+1)); err == nil {
		t.Error("route publique : un corps de plus de 64 Kio doit être refusé")
	}
	if _, err := readAll(nil, "/internal/v1/pair", strings.Repeat("x", maxPublicBody+1)); err == nil {
		t.Error("appairage : un corps de plus de 64 Kio doit être refusé")
	}
	if n, err := readAll(nil, "/api/v1/import", strings.Repeat("x", 33<<20)); err != nil || n != 33<<20 {
		t.Errorf("une route authentifiée garde ses 32 Mio d'import : n=%d err=%v", n, err)
	}
	if _, err := readAll(nil, "/api/v1/proxies", strings.Repeat("x", maxAPIBody+1)); err == nil {
		t.Error("au-delà de 64 Mio, même une route authentifiée est refusée")
	}
}

func TestLimitRequestBodies_AnnouncedSizeRefusedUpFront(t *testing.T) {
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", strings.NewReader("x"))
	req.ContentLength = maxPublicBody + 1
	called := false
	limitRequestBodies(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { called = true })).ServeHTTP(rec, req)
	if rec.Code != http.StatusRequestEntityTooLarge || called {
		t.Errorf("code=%d appelé=%v : une taille annoncée trop grande doit être refusée avant le handler", rec.Code, called)
	}
}
