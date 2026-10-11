// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package httpx

import (
	"bufio"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

func TestHarden_SetsMissingTimeoutsAndKeepsExistingOnes(t *testing.T) {
	s := Harden(&http.Server{})
	if s.ReadHeaderTimeout != HeaderTimeout || s.IdleTimeout != IdleTimeout {
		t.Errorf("délais par défaut = %v / %v", s.ReadHeaderTimeout, s.IdleTimeout)
	}
	s = Harden(&http.Server{ReadHeaderTimeout: time.Second, IdleTimeout: time.Minute})
	if s.ReadHeaderTimeout != time.Second || s.IdleTimeout != time.Minute {
		t.Errorf("un délai fixé est conservé : %v / %v", s.ReadHeaderTimeout, s.IdleTimeout)
	}
}

// Un client qui n'achève jamais ses en-têtes voit sa connexion fermée par le serveur.
func TestHarden_ClosesSlowHeaderClients(t *testing.T) {
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {}))
	srv.Config.ReadHeaderTimeout = 150 * time.Millisecond
	srv.Start()
	defer srv.Close()
	conn, err := net.Dial("tcp", strings.TrimPrefix(srv.URL, "http://"))
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("GET / HTTP/1.1\r\nHost: x\r\nX-Slow: ")) //nolint:errcheck
	conn.SetReadDeadline(time.Now().Add(3 * time.Second))
	_, err = bufio.NewReader(conn).ReadString('\n')
	if err == nil {
		return // le serveur a répondu (408) puis fermé
	}
	if ne, ok := err.(net.Error); ok && ne.Timeout() {
		t.Fatal("la connexion lente est restée ouverte")
	}
}
