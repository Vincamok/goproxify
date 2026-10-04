// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"fmt"
	"io"
	"net"
	"net/http"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
)

func proxyProtocolServer(enabled bool, cidrs ...string) *Server {
	cfg := &config.EdgeConfig{}
	cfg.Network.ProxyProtocol.Enabled = enabled
	cfg.Network.ProxyProtocol.TrustedCIDRs = cidrs
	return &Server{cfg: cfg}
}

func TestWithProxyProtocol_DisabledReturnsListenerAsIs(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	defer ln.Close()
	got, err := proxyProtocolServer(false).withProxyProtocol(ln)
	if err != nil || got != ln {
		t.Fatalf("got=%v err=%v", got, err)
	}
}

func TestWithProxyProtocol_RequiresTrustedSources(t *testing.T) {
	ln, _ := net.Listen("tcp", "127.0.0.1:0")
	if _, err := proxyProtocolServer(true).withProxyProtocol(ln); err == nil {
		t.Fatal("activer proxy_protocol sans trusted_cidrs doit échouer")
	}
	ln2, _ := net.Listen("tcp", "127.0.0.1:0")
	if _, err := proxyProtocolServer(true, "pas-une-ip").withProxyProtocol(ln2); err == nil {
		t.Fatal("un CIDR invalide doit échouer")
	}
}

// Le serveur HTTP voit l'IP annoncée par le load balancer dans r.RemoteAddr.
func TestWithProxyProtocol_HTTPServerSeesClientIP(t *testing.T) {
	raw, _ := net.Listen("tcp", "127.0.0.1:0")
	ln, err := proxyProtocolServer(true, "127.0.0.1").withProxyProtocol(raw)
	if err != nil {
		t.Fatal(err)
	}
	srv := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprint(w, r.RemoteAddr)
	})}
	go srv.Serve(ln) //nolint:errcheck
	defer srv.Close()

	c, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	fmt.Fprint(c, "PROXY TCP4 203.0.113.7 10.0.0.1 51000 80\r\nGET / HTTP/1.1\r\nHost: x\r\nConnection: close\r\n\r\n")
	body, _ := io.ReadAll(c)
	if want := "203.0.113.7:51000"; !strings.Contains(string(body), want) {
		t.Fatalf("réponse %q ne contient pas %s", body, want)
	}
}

