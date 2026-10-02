// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestSecurityHeadersHideServerStripsBackendHeaders(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Add("Server", "nginx/1.25")
		w.Header().Add("X-Powered-By", "PHP/8")
		w.Header().Set("X-Other", "kept")
		_, _ = w.Write([]byte("ok"))
	})
	h := SecurityHeaders(&router.HeadersConfig{HideServer: true})(backend)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if v := rr.Header().Values("Server"); len(v) != 0 {
		t.Fatalf("Server = %v", v)
	}
	if v := rr.Header().Values("X-Powered-By"); len(v) != 0 {
		t.Fatalf("X-Powered-By = %v", v)
	}
	if rr.Header().Get("X-Other") != "kept" {
		t.Fatal("les autres en-têtes doivent rester")
	}
}

func TestSecurityHeadersHideServerOff(t *testing.T) {
	backend := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Server", "nginx")
	})
	h := SecurityHeaders(&router.HeadersConfig{})(backend)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/", nil))
	if rr.Header().Get("Server") != "nginx" {
		t.Fatal("Server doit être conservé sans hide_server")
	}
}
