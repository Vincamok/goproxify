// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package wsclient

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/agent/edgeset"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// liveEdge simule une passerelle qui accepte le HMAC de l'Agent, lit son register, lui annonce les
// autres membres du groupe et garde la connexion ouverte.
func liveEdge(t *testing.T, registered *atomic.Int32, announce []string) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Agent-HMAC") != "hmac-agent" {
			http.Error(w, "refusé", http.StatusForbidden)
			return
		}
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		defer conn.CloseNow()
		var reg edgeWS.Message
		if err := wsjson.Read(r.Context(), conn, &reg); err != nil || reg.Type != edgeWS.TypeAgentRegister {
			return
		}
		registered.Add(1)
		msg, _ := edgeWS.NewMessage(1, edgeWS.TypeEdgeEndpoints, edgeWS.EdgeEndpointsPayload{Endpoints: announce})
		_ = wsjson.Write(r.Context(), conn, msg)
		for {
			var m edgeWS.Message
			if err := wsjson.Read(r.Context(), conn, &m); err != nil {
				return
			}
		}
	}))
	t.Cleanup(srv.Close)
	return srv
}

// Quand la passerelle principale reste injoignable, l'Agent bascule vers un autre membre du groupe
// connu, s'y connecte avec son HMAC et en est informé.
func TestClientFailsOverToGroupMember(t *testing.T) {
	var registered atomic.Int32
	member := liveEdge(t, &registered, []string{"http://edge-c:8000"})

	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close() // la passerelle configurée est tombée

	set := edgeset.New(deadURL, "")
	set.Update([]string{member.URL})

	switched := make(chan string, 1)
	c := NewClient("agent-1", "agent-1", "test", deadURL, "", "hmac-agent", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer c.Close()
	c.SetEdgeSet(set, func(edge string) { switched <- edge })

	select {
	case edge := <-switched:
		if edge != member.URL {
			t.Fatalf("bascule vers %q, attendu %q", edge, member.URL)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("pas de bascule vers le membre du groupe")
	}

	deadline := time.Now().Add(10 * time.Second)
	for registered.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if registered.Load() == 0 {
		t.Fatal("l'Agent ne s'est pas connecté au membre du groupe")
	}
	if set.Current() != member.URL {
		t.Fatalf("passerelle courante : %q", set.Current())
	}

	// L'annonce du membre est retenue et la passerelle courante n'est pas quittée.
	deadline = time.Now().Add(5 * time.Second)
	for set.Len() < 3 && time.Now().Before(deadline) {
		time.Sleep(50 * time.Millisecond)
	}
	if set.Len() != 3 || set.Current() != member.URL {
		t.Fatalf("après annonce : len=%d courante=%q", set.Len(), set.Current())
	}
}

// Sans autre membre connu, l'Agent reste sur sa passerelle et continue de réessayer.
func TestClientWithoutGroupDoesNotSwitch(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	deadURL := dead.URL
	dead.Close()

	set := edgeset.New(deadURL, "")
	var switched atomic.Int32
	c := NewClient("agent-1", "agent-1", "test", deadURL, "", "hmac-agent", nil, slog.New(slog.NewTextHandler(io.Discard, nil)))
	defer c.Close()
	c.SetEdgeSet(set, func(string) { switched.Add(1) })

	time.Sleep(6 * time.Second)
	if switched.Load() != 0 {
		t.Fatal("aucune bascule possible sans autre membre")
	}
	if set.Current() != deadURL {
		t.Fatalf("courante : %q", set.Current())
	}
}
