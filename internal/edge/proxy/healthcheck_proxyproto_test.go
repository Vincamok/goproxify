// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"net"
	"net/http"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/proxyproto"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// ppOnlyBackend refuse toute connexion qui ne commence pas par un en-tête PROXY, comme un backend
// derrière `accept-proxy` ; il répond 200 aux requêtes HTTP qui suivent l'en-tête.
func ppOnlyBackend(t *testing.T, firstLine chan<- string) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				head, _ := br.Peek(5)
				if string(head) != "PROXY" {
					return
				}
				line, _ := br.ReadString('\n')
				select {
				case firstLine <- strings.TrimSpace(line):
				default:
				}
				if req, err := http.ReadRequest(br); err == nil {
					req.Body.Close()
					c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: 0\r\nConnection: close\r\n\r\n")) //nolint:errcheck
				}
			}()
		}
	}()
	return ln.Addr().String()
}

func TestProbeWritesProxyProtocolHeader(t *testing.T) {
	line := make(chan string, 4)
	addr := ppOnlyBackend(t, line)
	cfg := defaultProbeConfig()
	cfg.proxyProtocol = "v1"
	if !probeWithConfig("http://"+addr, cfg) {
		t.Fatal("la sonde doit réussir quand elle écrit l'en-tête PROXY")
	}
	select {
	case got := <-line:
		if got != "PROXY UNKNOWN" {
			t.Fatalf("en-tête de sonde = %q, attendu PROXY UNKNOWN (aucun client réel)", got)
		}
	case <-time.After(time.Second):
		t.Fatal("le backend n'a reçu aucun en-tête")
	}
}


func TestProbeV2WritesLocalHeader(t *testing.T) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	got := make(chan []byte, 1)
	go func() {
		c, err := ln.Accept()
		if err != nil {
			return
		}
		defer c.Close()
		buf := make([]byte, 16)
		n, _ := c.Read(buf)
		got <- buf[:n]
	}()
	if !tcpReachable(ln.Addr().String(), time.Second, "v2") {
		t.Fatal("backend injoignable")
	}
	want := proxyproto.Header("v2", netipZero(), netipZero())
	select {
	case b := <-got:
		if string(b) != string(want) {
			t.Fatalf("en-tête v2 = %x, attendu %x (LOCAL)", b, want)
		}
	case <-time.After(time.Second):
		t.Fatal("rien reçu")
	}
}

func TestSyncCarriesProxyProtocolToProbe(t *testing.T) {
	h := NewBackendHealth(nil)
	rt := &router.Route{ID: "r1", ProxyProtocol: "v2", Backends: []router.Backend{{URL: "http://127.0.0.1:1"}}}
	h.Sync([]*router.Route{rt})
	defer h.Sync(nil)
	h.mu.RLock()
	defer h.mu.RUnlock()
	if p := h.probes[probeKey{"r1", "http://127.0.0.1:1"}]; p == nil || p.cfg.proxyProtocol != "v2" {
		t.Fatalf("sonde sans proxy_protocol : %+v", p)
	}
}

func netipZero() (a netip.AddrPort) { return }
