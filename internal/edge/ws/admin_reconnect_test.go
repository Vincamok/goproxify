// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package ws

import (
	"context"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"nhooyr.io/websocket"
)

func dialAdmin(t *testing.T, srv *httptest.Server, secret string) *websocket.Conn {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	c, _, err := websocket.Dial(ctx, "ws"+strings.TrimPrefix(srv.URL, "http")+"/ws/admin", &websocket.DialOptions{
		HTTPHeader: http.Header{
			hmacHeader:  {BuildAdminSignature(secret, http.MethodGet, "/ws/admin")},
			"X-Node-ID": {"admin-1"},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func adminConnCount(h *Hub) int {
	h.mu.Lock()
	defer h.mu.Unlock()
	return len(h.adminConns)
}

func TestAdminReconnectKeepsNewConnectionWhenOldOneCloses(t *testing.T) {
	const secret = "pairing-secret-test"
	h := NewHub(secret, slog.Default())
	mux := http.NewServeMux()
	mux.HandleFunc("/ws/admin", h.ServeAdmin)
	srv := httptest.NewServer(mux)
	defer srv.Close()

	old := dialAdmin(t, srv, secret)
	waitFor(t, func() bool { return adminConnCount(h) == 1 })
	fresh := dialAdmin(t, srv, secret)
	defer fresh.Close(websocket.StatusNormalClosure, "")
	time.Sleep(100 * time.Millisecond)

	old.Close(websocket.StatusNormalClosure, "")
	time.Sleep(300 * time.Millisecond)

	if n := adminConnCount(h); n != 1 {
		t.Fatalf("la fermeture de l'ancienne connexion a effacé la nouvelle : %d connexion(s) suivie(s), attendu 1", n)
	}
}

func waitFor(t *testing.T, cond func() bool) {
	t.Helper()
	for i := 0; i < 100; i++ {
		if cond() {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("condition non atteinte")
}
