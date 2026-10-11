// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package stream

import (
	"context"
	"net"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func routeOf(lb router.LBAlgorithm, backends ...router.Backend) *router.Route {
	return &router.Route{ID: "r", Type: router.RouteTCP, LB: lb, Backends: backends}
}

func TestPool_RoundRobinRotatesThroughHealthyBackends(t *testing.T) {
	p := newPool(routeOf("", router.Backend{URL: "a:1"}, router.Backend{URL: "b:1"}, router.Backend{URL: "c:1"}))
	seen := map[string]int{}
	for i := 0; i < 30; i++ {
		seen[p.pick().URL]++
	}
	if seen["a:1"] != 10 || seen["b:1"] != 10 || seen["c:1"] != 10 {
		t.Errorf("répartition = %v, attendu 10/10/10", seen)
	}
}

func TestPool_WeightedFollowsWeights(t *testing.T) {
	p := newPool(routeOf(router.LBWeighted, router.Backend{URL: "a:1", Weight: 3}, router.Backend{URL: "b:1", Weight: 1}))
	seen := map[string]int{}
	for i := 0; i < 400; i++ {
		seen[p.pick().URL]++
	}
	if seen["a:1"] != 300 || seen["b:1"] != 100 {
		t.Errorf("répartition pondérée = %v, attendu 300/100", seen)
	}
}

func TestPool_DownBackendsAreTriedLast(t *testing.T) {
	p := newPool(routeOf("", router.Backend{URL: "a:1"}, router.Backend{URL: "b:1"}))
	p.markDown("a:1")
	for i := 0; i < 5; i++ {
		o := p.order()
		if len(o) != 2 || o[0].URL != "b:1" || o[1].URL != "a:1" {
			t.Fatalf("ordre = %v : le backend écarté passe en dernier", o)
		}
	}
	p.markUp("a:1")
	if o := p.order(); len(o) != 2 {
		t.Fatalf("ordre = %v", o)
	}
	seen := map[string]bool{}
	for i := 0; i < 4; i++ {
		seen[p.pick().URL] = true
	}
	if !seen["a:1"] || !seen["b:1"] {
		t.Error("un backend rétabli doit recevoir de nouveau du trafic")
	}
}

func TestPool_AllDownStillTries(t *testing.T) {
	p := newPool(routeOf("", router.Backend{URL: "a:1"}, router.Backend{URL: "b:1"}))
	p.markDown("a:1")
	p.markDown("b:1")
	if p.pick() == nil || len(p.order()) != 2 {
		t.Error("quand tous sont écartés, on retente quand même plutôt que de tout refuser")
	}
}

func TestPool_EmptyRoute(t *testing.T) {
	if newPool(routeOf("")).pick() != nil {
		t.Error("une route sans backend n'a rien à choisir")
	}
}

func deadAddr(t *testing.T) string {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := ln.Addr().String()
	ln.Close()
	return addr
}

// Un backend mort en tête de liste n'empêche pas la connexion : le suivant est essayé, et le mort est écarté.
func TestPool_DialFailsOverToNextBackend(t *testing.T) {
	dead, alive := deadAddr(t), echoTCP(t)
	p := newPool(routeOf("", router.Backend{URL: dead}, router.Backend{URL: alive}))
	c, b, err := p.dialTCP(time.Second)
	if err != nil {
		t.Fatalf("aucun backend joint : %v", err)
	}
	c.Close()
	if b.URL != alive {
		t.Errorf("backend = %s, attendu %s", b.URL, alive)
	}
	if o := p.order(); o[0].URL != alive {
		t.Errorf("le backend mort doit être écarté, ordre = %v", o)
	}
}

func TestPool_DialAllDeadReturnsError(t *testing.T) {
	p := newPool(routeOf("", router.Backend{URL: deadAddr(t)}, router.Backend{URL: deadAddr(t)}))
	if _, _, err := p.dialTCP(time.Second); err == nil {
		t.Fatal("aucun backend ne répond : une erreur est attendue")
	}
}

func TestPool_ActiveProbeRemovesAndRestoresBackend(t *testing.T) {
	// b est d'abord mort, puis démarre à la même adresse.
	bAddr := deadAddr(t)
	p := newPool(routeOf("", router.Backend{URL: echoTCP(t)}, router.Backend{URL: bAddr}))
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	go p.probe(ctx, &router.HealthCheckConfig{Interval: 50 * time.Millisecond, Timeout: 100 * time.Millisecond})

	waitFor(t, "b écarté par la sonde", func() bool {
		o := p.order()
		return o[len(o)-1].URL == bAddr && o[0].URL != bAddr
	})
	ln, err := net.Listen("tcp", bAddr)
	if err != nil {
		t.Skipf("adresse reprise par un autre processus : %v", err)
	}
	defer ln.Close()
	waitFor(t, "b rétabli par la sonde", func() bool {
		p.mu.Lock()
		defer p.mu.Unlock()
		return !p.st(bAddr).probeDown
	})
}

func waitFor(t *testing.T, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for !cond() {
		if time.Now().After(deadline) {
			t.Fatalf("délai dépassé : %s", what)
		}
		time.Sleep(20 * time.Millisecond)
	}
}

func TestPool_ProbeThresholds(t *testing.T) {
	p := newPool(routeOf("", router.Backend{URL: "a:1"}))
	p.recordProbe("a:1", false, 2, 2)
	if p.st("a:1").probeDown {
		t.Error("un seul échec ne suffit pas avec un seuil de 2")
	}
	p.recordProbe("a:1", false, 2, 2)
	if !p.st("a:1").probeDown {
		t.Error("deux échecs consécutifs écartent le backend")
	}
	p.recordProbe("a:1", true, 2, 2)
	if !p.st("a:1").probeDown {
		t.Error("un seul succès ne suffit pas à le rétablir")
	}
	p.recordProbe("a:1", true, 2, 2)
	if p.st("a:1").probeDown {
		t.Error("deux succès consécutifs le rétablissent")
	}
}

// Une session UDP dont le backend répond « port unreachable » écarte ce backend : la session suivante prend l'autre.
func TestUDP_UnreachableBackendIsMarkedDown(t *testing.T) {
	if !icmpUnreachableDelivered(t) {
		t.Skip("cette plateforme ne remonte pas l'ICMP « port unreachable » sur un socket UDP connecté (Linux le fait)")
	}
	dead := newUDPBackend(t)
	deadAddr := dead.conn.LocalAddr().String()
	dead.conn.Close() // plus rien n'écoute : le noyau renvoie « port unreachable »
	alive := newUDPBackend(t)
	l := NewUDPListener(&router.Route{ID: "u", Type: router.RouteUDP, Backends: []router.Backend{{URL: deadAddr}, {URL: alive.conn.LocalAddr().String()}}}, testLog, &Metrics{})
	l.pool.turn = 0
	conn, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1)})
	if err != nil {
		t.Fatal(err)
	}
	l.conn = conn
	go l.loop()
	defer l.Stop()
	c := udpClient(t, conn.LocalAddr().String())
	c.Write([]byte("x")) //nolint:errcheck
	waitFor(t, "backend mort écarté", func() bool {
		l.pool.mu.Lock()
		defer l.pool.mu.Unlock()
		return !l.pool.healthy(deadAddr, time.Now())
	})
}

// icmpUnreachableDelivered : un socket UDP connecté vers un port fermé reçoit-il une erreur de lecture ?
func icmpUnreachableDelivered(t *testing.T) bool {
	t.Helper()
	c, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	addr := c.LocalAddr().(*net.UDPAddr)
	c.Close()
	conn, err := net.DialUDP("udp", nil, addr)
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	conn.Write([]byte("x")) //nolint:errcheck
	conn.SetReadDeadline(time.Now().Add(500 * time.Millisecond))
	_, err = conn.Read(make([]byte, 16))
	ne, isNet := err.(net.Error)
	return err != nil && !(isNet && ne.Timeout())
}
