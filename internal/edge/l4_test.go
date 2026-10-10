// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"io"
	"net"
	"strconv"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func freeTCPPort(t *testing.T) int {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	return c.LocalAddr().(*net.UDPAddr).Port
}

// echoBackend renvoie tout ce qu'il reçoit et compte les connexions.
func echoBackend(t *testing.T) (addr string, conns *atomic.Int32) {
	t.Helper()
	conns = &atomic.Int32{}
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { l.Close() })
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			conns.Add(1)
			go func() { defer c.Close(); _, _ = io.Copy(c, c) }()
		}
	}()
	return l.Addr().String(), conns
}

func l4TestServer(t *testing.T) *Server {
	s := pluginTestServer(t, t.TempDir())
	s.table.SetOnChange(s.scheduleL4Sync)
	t.Cleanup(func() {
		s.l4.stop()
		s.mu.Lock()
		for _, l := range s.tcpPorts {
			l.Stop()
		}
		s.mu.Unlock()
	})
	return s
}

func dialEventually(t *testing.T, addr string) net.Conn {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", addr, 200*time.Millisecond)
		if err == nil {
			return c
		}
		if time.Now().After(deadline) {
			t.Fatalf("écouteur %s jamais ouvert : %v", addr, err)
		}
		time.Sleep(50 * time.Millisecond)
	}
}

func roundTrip(c net.Conn, msg string) (string, error) {
	_ = c.SetDeadline(time.Now().Add(time.Second))
	if _, err := c.Write([]byte(msg)); err != nil {
		return "", err
	}
	buf := make([]byte, len(msg))
	_, err := io.ReadFull(c, buf)
	return string(buf), err
}

// Les routes TCP suivent la table : l'écouteur s'ouvre à l'ajout, se ferme à la suppression.
func TestL4_ListenerFollowsTheTable(t *testing.T) {
	s := l4TestServer(t)
	backend, _ := echoBackend(t)
	port := freeTCPPort(t)
	s.table.Upsert(&router.Route{ID: "l4-tcp", Type: router.RouteTCP, ListenPort: port, Backends: []router.Backend{{URL: backend}}})

	c := dialEventually(t, "127.0.0.1:"+strconv.Itoa(port))
	if got, err := roundTrip(c, "bonjour"); err != nil || got != "bonjour" {
		t.Fatalf("relais TCP : %q %v", got, err)
	}
	c.Close()

	s.table.Delete("l4-tcp")
	deadline := time.Now().Add(3 * time.Second)
	for {
		c, err := net.DialTimeout("tcp", "127.0.0.1:"+strconv.Itoa(port), 200*time.Millisecond)
		if err != nil {
			break
		}
		c.Close()
		if time.Now().After(deadline) {
			t.Fatal("écouteur toujours ouvert après la suppression de la route")
		}
		time.Sleep(50 * time.Millisecond)
	}
}

// Le hook connect refuse la connexion avant tout appel au backend.
func TestL4_ConnectHookGatesTCP(t *testing.T) {
	s := l4TestServer(t)
	backend, conns := echoBackend(t)
	installBody(t, s, "gate-deny", `{"action":"deny"}`, []string{"connect"}, nil)
	installBody(t, s, "gate-allow", `{"action":"allow"}`, []string{"connect"}, nil)

	deniedPort, allowedPort := freeTCPPort(t), freeTCPPort(t)
	s.table.Upsert(&router.Route{ID: "l4-deny", Type: router.RouteTCP, ListenPort: deniedPort, Backends: []router.Backend{{URL: backend}},
		Plugins: []router.PluginRef{{Name: "gate-deny"}}})
	s.table.Upsert(&router.Route{ID: "l4-allow", Type: router.RouteTCP, ListenPort: allowedPort, Backends: []router.Backend{{URL: backend}},
		Plugins: []router.PluginRef{{Name: "gate-allow"}}})

	c := dialEventually(t, "127.0.0.1:"+strconv.Itoa(deniedPort))
	if _, err := roundTrip(c, "x"); err == nil {
		t.Error("connexion refusée par le plugin mais relayée")
	}
	c.Close()
	if n := conns.Load(); n != 0 {
		t.Errorf("le backend a reçu %d connexion(s) malgré le refus", n)
	}
	c = dialEventually(t, "127.0.0.1:"+strconv.Itoa(allowedPort))
	if got, err := roundTrip(c, "salut"); err != nil || got != "salut" {
		t.Errorf("connexion autorisée : %q %v", got, err)
	}
	c.Close()
}

// Un plugin absent refuse les connexions L4 (comme pour une route HTTP).
func TestL4_MissingPluginFailsClosed(t *testing.T) {
	s := l4TestServer(t)
	backend, conns := echoBackend(t)
	port := freeTCPPort(t)
	s.table.Upsert(&router.Route{ID: "l4-missing", Type: router.RouteTCP, ListenPort: port, Backends: []router.Backend{{URL: backend}},
		Plugins: []router.PluginRef{{Name: "pas-installe"}}})
	c := dialEventually(t, "127.0.0.1:"+strconv.Itoa(port))
	defer c.Close()
	if _, err := roundTrip(c, "x"); err == nil || conns.Load() != 0 {
		t.Errorf("plugin absent : relayé (err=%v, connexions backend=%d)", err, conns.Load())
	}
}

func TestL4_UDPGate(t *testing.T) {
	s := l4TestServer(t)
	// Backend UDP en écho.
	bc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { bc.Close() })
	go func() {
		buf := make([]byte, 2048)
		for {
			n, addr, err := bc.ReadFrom(buf)
			if err != nil {
				return
			}
			_, _ = bc.WriteTo(buf[:n], addr)
		}
	}()
	installBody(t, s, "udp-deny", `{"action":"deny"}`, []string{"connect"}, nil)
	installBody(t, s, "udp-allow", `{"action":"allow"}`, []string{"connect"}, nil)
	ask := func(port int) (string, error) {
		c, err := net.Dial("udp", "127.0.0.1:"+strconv.Itoa(port))
		if err != nil {
			return "", err
		}
		defer c.Close()
		_ = c.SetDeadline(time.Now().Add(500 * time.Millisecond))
		if _, err := c.Write([]byte("ping")); err != nil {
			return "", err
		}
		buf := make([]byte, 16)
		n, err := c.Read(buf)
		return string(buf[:n]), err
	}
	for _, tc := range []struct {
		plugin string
		want   bool
	}{{"udp-allow", true}, {"udp-deny", false}} {
		port := freeUDPPort(t)
		s.table.Upsert(&router.Route{ID: "udp-" + tc.plugin, Type: router.RouteUDP, ListenPort: port, Backends: []router.Backend{{URL: bc.LocalAddr().String()}},
			Plugins: []router.PluginRef{{Name: tc.plugin}}})
		var got string
		var err error
		deadline := time.Now().Add(3 * time.Second)
		for { // l'écouteur s'ouvre après le regroupement des changements de table
			got, err = ask(port)
			if err == nil || !tc.want || time.Now().After(deadline) {
				break
			}
			time.Sleep(100 * time.Millisecond)
		}
		if tc.want && (err != nil || got != "ping") {
			t.Errorf("%s : %q %v", tc.plugin, got, err)
		}
		if !tc.want && err == nil {
			t.Errorf("%s : datagramme relayé malgré le refus", tc.plugin)
		}
	}
}
