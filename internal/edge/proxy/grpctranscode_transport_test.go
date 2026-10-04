// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func h2cBackend(t *testing.T) (*httptest.Server, *int) {
	t.Helper()
	major := new(int)
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*major = r.ProtoMajor
		w.WriteHeader(http.StatusNoContent)
	}))
	var p http.Protocols
	p.SetHTTP1(true)
	p.SetUnencryptedHTTP2(true)
	srv.Config.Protocols = &p
	srv.Start()
	t.Cleanup(srv.Close)
	return srv, major
}

func TestBuildTransport_GRPCTranscodeSpeaksH2C(t *testing.T) {
	srv, major := h2cBackend(t)
	rt := buildTransport(&router.Route{GRPCTranscode: &router.GRPCTranscodeConfig{Enabled: true}})
	resp, err := rt.RoundTrip(httptest.NewRequest("POST", srv.URL+"/demo.v1.Users/GetUser", nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *major != 2 {
		t.Fatalf("le backend http:// doit être joint en HTTP/2 (h2c), reçu HTTP/%d", *major)
	}
}

func TestBuildTransport_NoH2CWithoutGRPCTranscode(t *testing.T) {
	srv, major := h2cBackend(t)
	rt := buildTransport(&router.Route{})
	resp, err := rt.RoundTrip(httptest.NewRequest("POST", srv.URL+"/x", nil))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if *major != 1 {
		t.Fatalf("sans transcodage, HTTP/1.1 attendu, reçu HTTP/%d", *major)
	}
}
