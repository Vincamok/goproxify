// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"bufio"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// unwrapWriter imite les enveloppes de l'Admin (journal d'accès) : Flush et Unwrap, rien d'autre.
type unwrapWriter struct{ http.ResponseWriter }

func (w unwrapWriter) Unwrap() http.ResponseWriter { return w.ResponseWriter }
func (w unwrapWriter) Flush()                      { w.ResponseWriter.(http.Flusher).Flush() }

func sseServer(t *testing.T, writeTimeout time.Duration) *httptest.Server {
	t.Helper()
	h := &Handler{}
	srv := httptest.NewUnstartedServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h.serveSSE(unwrapWriter{w}, r)
	}))
	srv.Config.WriteTimeout = writeTimeout
	srv.Start()
	t.Cleanup(srv.Close)
	return srv
}

// Le WriteTimeout du serveur est un plafond sur toute la réponse : sans correction, il coupe le flux SSE au bout de
// WriteTimeout alors que des keepalives continuent de partir.
func TestSSEOutlivesServerWriteTimeout(t *testing.T) {
	oldK, oldW := sseKeepalive, sseWriteWindow
	sseKeepalive, sseWriteWindow = 50*time.Millisecond, 2*time.Second
	t.Cleanup(func() { sseKeepalive, sseWriteWindow = oldK, oldW })

	srv := sseServer(t, 200*time.Millisecond)
	resp, err := http.Get(srv.URL + "/mcp/sse")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()

	keepalives := 0
	deadline := time.After(1200 * time.Millisecond)
	lines := make(chan string)
	go func() {
		sc := bufio.NewScanner(resp.Body)
		for sc.Scan() {
			lines <- sc.Text()
		}
		close(lines)
	}()
	for {
		select {
		case l, ok := <-lines:
			if !ok {
				t.Fatalf("flux coupé par le serveur après %d keepalives (WriteTimeout 200 ms)", keepalives)
			}
			if strings.HasPrefix(l, ": keepalive") {
				keepalives++
			}
		case <-deadline:
			if keepalives < 15 {
				t.Fatalf("%d keepalives en 1,2 s, attendu au moins 15", keepalives)
			}
			return
		}
	}
}
