// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"errors"
	"io"
	"log/slog"
	"net"
	"sync/atomic"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

var testLog = slog.New(slog.NewTextHandler(io.Discard, nil))

func echoTCP(t *testing.T) string {
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
			go func() { defer c.Close(); io.Copy(c, c) }() //nolint:errcheck
		}
	}()
	return ln.Addr().String()
}

func startTCP(t *testing.T, backend string) (*TCPListener, string) {
	t.Helper()
	l := NewTCPListener(&router.Route{ID: "t", Type: router.RouteTCP, Backends: []router.Backend{{URL: backend}}}, testLog, &Metrics{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.listener = ln
	go l.accept()
	t.Cleanup(l.Stop)
	return l, ln.Addr().String()
}

func roundTrip(t *testing.T, addr string) (net.Conn, bool) {
	t.Helper()
	c, err := net.Dial("tcp", addr)
	if err != nil {
		t.Fatal(err)
	}
	c.SetDeadline(time.Now().Add(2 * time.Second))
	if _, err := c.Write([]byte("ping")); err != nil {
		return c, false
	}
	buf := make([]byte, 4)
	_, err = io.ReadFull(c, buf)
	return c, err == nil && string(buf) == "ping"
}

func TestTCP_ForwardsToBackend(t *testing.T) {
	_, addr := startTCP(t, echoTCP(t))
	c, ok := roundTrip(t, addr)
	defer c.Close()
	if !ok {
		t.Fatal("l'écho via le proxy ne fonctionne pas")
	}
}

// Au-delà du plafond de connexions simultanées, la connexion est refusée ; une place libérée est réutilisable.
func TestTCP_ConnectionCap(t *testing.T) {
	t.Setenv("GPX_STREAM_MAX_CONNS", "2")
	_, addr := startTCP(t, echoTCP(t))
	c1, ok1 := roundTrip(t, addr)
	c2, ok2 := roundTrip(t, addr)
	defer c2.Close()
	if !ok1 || !ok2 {
		t.Fatal("les deux premières connexions doivent passer")
	}
	c3, ok3 := roundTrip(t, addr)
	defer c3.Close()
	if ok3 {
		t.Fatal("la troisième connexion dépasse le plafond et doit être refusée")
	}
	c1.Close()
	time.Sleep(300 * time.Millisecond) // le jeton est rendu quand le handler se termine
	c4, ok4 := roundTrip(t, addr)
	defer c4.Close()
	if !ok4 {
		t.Fatal("une place libérée doit pouvoir être réutilisée")
	}
}

// fakeListener renvoie d'abord des erreurs transitoires (« too many open files »), puis une connexion, puis se ferme.
type fakeListener struct {
	errs   int32
	conn   net.Conn
	closed chan struct{}
}

func (f *fakeListener) Accept() (net.Conn, error) {
	if atomic.AddInt32(&f.errs, -1) >= 0 {
		return nil, errors.New("accept: too many open files")
	}
	if f.conn != nil {
		c := f.conn
		f.conn = nil
		return c, nil
	}
	<-f.closed
	return nil, net.ErrClosed
}
func (f *fakeListener) Close() error   { return nil }
func (f *fakeListener) Addr() net.Addr { return &net.TCPAddr{} }

// Une erreur d'Accept transitoire ne doit pas arrêter la boucle : le port resterait ouvert mais mort.
func TestTCP_AcceptLoopSurvivesTransientErrors(t *testing.T) {
	backend := echoTCP(t)
	client, server := net.Pipe()
	defer client.Close()
	fl := &fakeListener{errs: 3, conn: server, closed: make(chan struct{})}
	defer close(fl.closed)
	l := NewTCPListener(&router.Route{ID: "t", Type: router.RouteTCP, Backends: []router.Backend{{URL: backend}}}, testLog, &Metrics{})
	l.listener = fl
	go l.accept()
	client.SetDeadline(time.Now().Add(3 * time.Second))
	if _, err := client.Write([]byte("ping")); err != nil {
		t.Fatalf("la connexion arrivée après des erreurs transitoires n'est pas traitée : %v", err)
	}
	buf := make([]byte, 4)
	if _, err := io.ReadFull(client, buf); err != nil || string(buf) != "ping" {
		t.Fatalf("pas de réponse : %v %q", err, buf)
	}
}

func TestAcceptBackoff(t *testing.T) {
	defer func(f func(time.Duration)) { sleepFn = f }(sleepFn)
	sleepFn = func(time.Duration) {}
	var d time.Duration
	if !acceptBackoff(net.ErrClosed, &d) {
		t.Error("un écouteur fermé arrête la boucle")
	}
	for i := 0; i < 12; i++ {
		if acceptBackoff(errors.New("transitoire"), &d) {
			t.Fatal("une erreur transitoire ne doit pas arrêter la boucle")
		}
		if d > time.Second {
			t.Fatalf("délai %v > 1 s", d)
		}
	}
	if d != time.Second {
		t.Errorf("le délai doit plafonner à 1 s, %v", d)
	}
}

func TestUDP_ForwardsDatagramAndReply(t *testing.T) {
	back, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer back.Close()
	go func() {
		buf := make([]byte, 1500)
		for {
			n, a, err := back.ReadFrom(buf)
			if err != nil {
				return
			}
			back.WriteTo(buf[:n], a) //nolint:errcheck
		}
	}()
	l := NewUDPListener(&router.Route{ID: "u", Type: router.RouteUDP, Backends: []router.Backend{{URL: back.LocalAddr().String()}}}, testLog, &Metrics{})
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l.conn = conn
	go l.loop()
	defer l.Stop()
	c, err := net.Dial("udp", conn.LocalAddr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("hello")) //nolint:errcheck
	buf := make([]byte, 16)
	n, err := c.Read(buf)
	if err != nil || string(buf[:n]) != "hello" {
		t.Fatalf("réponse UDP : %v %q", err, buf[:n])
	}
}

// udpBackend note la source de chaque datagramme reçu et répond selon le contenu : « multi » donne trois réponses.
type udpBackend struct {
	conn    net.PacketConn
	sources chan string
}

func newUDPBackend(t *testing.T) *udpBackend {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	b := &udpBackend{conn: c, sources: make(chan string, 64)}
	t.Cleanup(func() { c.Close() })
	go func() {
		buf := make([]byte, 1500)
		for {
			n, from, err := c.ReadFrom(buf)
			if err != nil {
				return
			}
			b.sources <- from.String()
			msg := string(buf[:n])
			if msg == "multi" {
				for i := 0; i < 3; i++ {
					c.WriteTo([]byte("part"), from) //nolint:errcheck
				}
				continue
			}
			c.WriteTo(buf[:n], from) //nolint:errcheck
		}
	}()
	return b
}

func startUDP(t *testing.T, backend string, setup func(*UDPListener)) (*UDPListener, string) {
	t.Helper()
	l := NewUDPListener(&router.Route{ID: "u", Type: router.RouteUDP, Backends: []router.Backend{{URL: backend}}}, testLog, &Metrics{})
	if setup != nil {
		setup(l)
	}
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l.conn = conn
	go l.loop()
	t.Cleanup(l.Stop)
	return l, conn.LocalAddr().String()
}

func udpClient(t *testing.T, addr string) net.Conn {
	t.Helper()
	c, err := net.Dial("udp", addr)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	return c
}

func readUDP(c net.Conn) (string, error) {
	c.SetReadDeadline(time.Now().Add(2 * time.Second))
	buf := make([]byte, 1500)
	n, err := c.Read(buf)
	return string(buf[:n]), err
}

// Un client garde la même source côté backend, et le backend peut répondre plusieurs fois à un datagramme.
func TestUDP_SessionKeepsOneBackendSourceAndRelaysEveryReply(t *testing.T) {
	be := newUDPBackend(t)
	l, addr := startUDP(t, be.conn.LocalAddr().String(), nil)
	c := udpClient(t, addr)
	c.Write([]byte("a")) //nolint:errcheck
	if got, err := readUDP(c); err != nil || got != "a" {
		t.Fatalf("première réponse : %q %v", got, err)
	}
	c.Write([]byte("b")) //nolint:errcheck
	if got, err := readUDP(c); err != nil || got != "b" {
		t.Fatalf("deuxième réponse : %q %v", got, err)
	}
	first, second := <-be.sources, <-be.sources
	if first != second {
		t.Errorf("le backend a vu deux sources (%s, %s) : la session n'est pas conservée", first, second)
	}
	c.Write([]byte("multi")) //nolint:errcheck
	for i := 0; i < 3; i++ {
		if got, err := readUDP(c); err != nil || got != "part" {
			t.Fatalf("réponse multiple %d : %q %v", i, got, err)
		}
	}
	l.mu.Lock()
	n := len(l.sessions)
	l.mu.Unlock()
	if n != 1 {
		t.Errorf("%d sessions, attendu 1", n)
	}
}

func TestUDP_TwoClientsTwoSessions(t *testing.T) {
	be := newUDPBackend(t)
	_, addr := startUDP(t, be.conn.LocalAddr().String(), nil)
	c1, c2 := udpClient(t, addr), udpClient(t, addr)
	c1.Write([]byte("un")) //nolint:errcheck
	c2.Write([]byte("deux")) //nolint:errcheck
	if got, _ := readUDP(c1); got != "un" {
		t.Errorf("client 1 : %q", got)
	}
	if got, _ := readUDP(c2); got != "deux" {
		t.Errorf("client 2 : %q (chaque client reçoit sa réponse)", got)
	}
	if a, b := <-be.sources, <-be.sources; a == b {
		t.Error("deux clients ne doivent pas partager la source côté backend")
	}
}

func TestUDP_IdleSessionExpires(t *testing.T) {
	be := newUDPBackend(t)
	l, addr := startUDP(t, be.conn.LocalAddr().String(), func(l *UDPListener) { l.idle = 150 * time.Millisecond })
	c := udpClient(t, addr)
	c.Write([]byte("a")) //nolint:errcheck
	readUDP(c)            //nolint:errcheck
	deadline := time.Now().Add(3 * time.Second)
	for {
		l.mu.Lock()
		n := len(l.sessions)
		l.mu.Unlock()
		if n == 0 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("la session inactive n'a pas été fermée")
		}
		time.Sleep(20 * time.Millisecond)
	}
	c.Write([]byte("b")) //nolint:errcheck
	if got, err := readUDP(c); err != nil || got != "b" {
		t.Fatalf("une nouvelle session doit se recréer : %q %v", got, err)
	}
	if a, b := <-be.sources, <-be.sources; a == b {
		t.Error("après expiration, la source côté backend change (nouvelle session)")
	}
}

func TestUDP_SessionCap(t *testing.T) {
	be := newUDPBackend(t)
	l, addr := startUDP(t, be.conn.LocalAddr().String(), func(l *UDPListener) { l.maxSessions = 2 })
	cs := []net.Conn{udpClient(t, addr), udpClient(t, addr), udpClient(t, addr)}
	for i, c := range cs {
		c.Write([]byte("x")) //nolint:errcheck
		got, err := readUDP(c)
		if i < 2 && (err != nil || got != "x") {
			t.Fatalf("client %d sous le plafond : %q %v", i, got, err)
		}
		if i == 2 && err == nil {
			t.Fatal("le troisième client dépasse le plafond de sessions : son datagramme doit être abandonné")
		}
	}
	l.mu.Lock()
	n := len(l.sessions)
	l.mu.Unlock()
	if n != 2 {
		t.Errorf("%d sessions, attendu 2", n)
	}
}

func TestUDP_StopClosesSessions(t *testing.T) {
	be := newUDPBackend(t)
	l, addr := startUDP(t, be.conn.LocalAddr().String(), nil)
	c := udpClient(t, addr)
	c.Write([]byte("a")) //nolint:errcheck
	readUDP(c)            //nolint:errcheck
	l.Stop()
	l.mu.Lock()
	n := len(l.sessions)
	l.mu.Unlock()
	if n != 0 {
		t.Errorf("%d sessions après Stop", n)
	}
}

func startTCPWithIdle(t *testing.T, backend string, idleSec int) string {
	t.Helper()
	l := NewTCPListener(&router.Route{ID: "t", Type: router.RouteTCP, IdleTimeoutSec: idleSec, Backends: []router.Backend{{URL: backend}}}, testLog, &Metrics{})
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	l.listener = ln
	go l.accept()
	t.Cleanup(l.Stop)
	return ln.Addr().String()
}

// Une connexion silencieuse dans les deux sens est fermée à l'échéance ; une connexion active ne l'est pas.
func TestTCP_IdleTimeout(t *testing.T) {
	addr := startTCPWithIdle(t, echoTCP(t), 1)

	idle, ok := roundTrip(t, addr)
	defer idle.Close()
	if !ok {
		t.Fatal("l'écho doit fonctionner avant l'échéance")
	}
	idle.SetReadDeadline(time.Now().Add(4 * time.Second))
	start := time.Now()
	if _, err := idle.Read(make([]byte, 1)); err == nil {
		t.Fatal("une connexion silencieuse doit être fermée")
	}
	if d := time.Since(start); d > 3*time.Second {
		t.Errorf("fermée après %v, attendu environ 1 s", d)
	}

	busy, ok := roundTrip(t, addr)
	defer busy.Close()
	if !ok {
		t.Fatal("écho")
	}
	for i := 0; i < 5; i++ { // 5 × 400 ms > 1 s d'inactivité autorisée : l'activité doit réarmer le minuteur
		time.Sleep(400 * time.Millisecond)
		busy.SetDeadline(time.Now().Add(2 * time.Second))
		if _, err := busy.Write([]byte("ping")); err != nil {
			t.Fatalf("écriture %d : la connexion active a été coupée : %v", i, err)
		}
		if _, err := io.ReadFull(busy, make([]byte, 4)); err != nil {
			t.Fatalf("lecture %d : la connexion active a été coupée : %v", i, err)
		}
	}
}

// Sans idle_timeout_sec, une connexion silencieuse reste ouverte (pools de connexions de bases de données).
func TestTCP_NoIdleTimeoutByDefault(t *testing.T) {
	addr := startTCPWithIdle(t, echoTCP(t), 0)
	c, ok := roundTrip(t, addr)
	defer c.Close()
	if !ok {
		t.Fatal("écho")
	}
	time.Sleep(1500 * time.Millisecond)
	c.SetDeadline(time.Now().Add(2 * time.Second))
	c.Write([]byte("ping")) //nolint:errcheck
	if _, err := io.ReadFull(c, make([]byte, 4)); err != nil {
		t.Fatalf("la connexion ne doit pas être coupée sans délai configuré : %v", err)
	}
}

func TestUDPIdle_RouteOverridesEnvironment(t *testing.T) {
	t.Setenv("GPX_STREAM_UDP_IDLE", "30")
	if d := udpIdle(&router.Route{IdleTimeoutSec: 5}); d != 5*time.Second {
		t.Errorf("route : %v", d)
	}
	if d := udpIdle(&router.Route{}); d != 30*time.Second {
		t.Errorf("variable d'environnement : %v", d)
	}
	t.Setenv("GPX_STREAM_UDP_IDLE", "")
	if d := udpIdle(&router.Route{}); d != DefaultUDPIdle {
		t.Errorf("défaut : %v", d)
	}
}
