// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"bufio"
	"context"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// ppBackend accepte des connexions HTTP/1.1 précédées d'un en-tête PROXY v1 et le renvoie dans le corps.
func ppBackend(t *testing.T) (addr string, conns *int) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ln.Close() })
	n := 0
	go func() {
		for {
			c, err := ln.Accept()
			if err != nil {
				return
			}
			n++
			go func() {
				defer c.Close()
				br := bufio.NewReader(c)
				hdr, err := br.ReadString('\n')
				if err != nil {
					return
				}
				req, err := http.ReadRequest(br)
				if err != nil {
					return
				}
				req.Body.Close()
				body := strings.TrimSpace(hdr)
				c.Write([]byte("HTTP/1.1 200 OK\r\nContent-Length: " + strconv.Itoa(len(body)) + "\r\nConnection: close\r\n\r\n" + body)) //nolint:errcheck
			}()
		}
	}()
	return ln.Addr().String(), &n
}


func TestBuildTransport_WritesProxyProtocolHeader(t *testing.T) {
	addr, _ := ppBackend(t)
	rt := buildTransport(&router.Route{ProxyProtocol: "v1"})

	req := httptest.NewRequest("GET", "http://"+addr+"/", nil)
	ctx := context.WithValue(req.Context(), ppClientKey{}, ppClient{remote: "203.0.113.7:51000", local: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}})
	resp, err := rt.RoundTrip(req.WithContext(ctx))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 200)
	n, _ := resp.Body.Read(buf)
	if got := string(buf[:n]); got != "PROXY TCP4 203.0.113.7 10.0.0.1 51000 443" {
		t.Fatalf("en-tête reçu par le backend = %q", got)
	}
}

func TestBuildTransport_ProxyProtocolNeverReusesConnection(t *testing.T) {
	addr, conns := ppBackend(t)
	rt := buildTransport(&router.Route{ProxyProtocol: "v1"})
	for _, client := range []string{"203.0.113.7:1", "198.51.100.2:2"} {
		req := httptest.NewRequest("GET", "http://"+addr+"/", nil)
		ctx := context.WithValue(req.Context(), ppClientKey{}, ppClient{remote: client, local: &net.TCPAddr{IP: net.ParseIP("10.0.0.1"), Port: 443}})
		resp, err := rt.RoundTrip(req.WithContext(ctx))
		if err != nil {
			t.Fatal(err)
		}
		buf := make([]byte, 200)
		n, _ := resp.Body.Read(buf)
		resp.Body.Close()
		if !strings.Contains(string(buf[:n]), strings.Split(client, ":")[0]) {
			t.Fatalf("le client %s a reçu l'en-tête d'un autre : %q", client, buf[:n])
		}
	}
	if *conns != 2 {
		t.Fatalf("%d connexions backend, attendu 2 (une par requête)", *conns)
	}
}

func TestBuildTransport_NoProxyProtocolByDefault(t *testing.T) {
	rt := buildTransport(&router.Route{})
	tr, ok := rt.(*http.Transport)
	if !ok || tr.DisableKeepAlives {
		t.Fatal("sans proxy_protocol, le transport garde le keep-alive")
	}
}
