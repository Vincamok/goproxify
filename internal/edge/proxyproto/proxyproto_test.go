// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxyproto

import (
	"io"
	"net"
	"net/netip"
	"testing"
	"time"
)

func listen(t *testing.T, trusted ...string) *Listener {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	prefixes, err := ParseTrusted(trusted)
	if err != nil {
		t.Fatal(err)
	}
	l := NewListener(ln, prefixes)
	t.Cleanup(func() { l.Close() })
	return l
}

// send ouvre une connexion, écrit payload et retourne la connexion acceptée côté serveur.
func send(t *testing.T, l *Listener, payload []byte) net.Conn {
	t.Helper()
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { c.Close() })
	if _, err := c.Write(payload); err != nil {
		t.Fatal(err)
	}
	type acc struct {
		c   net.Conn
		err error
	}
	ch := make(chan acc, 1)
	go func() {
		sc, err := l.Accept()
		ch <- acc{sc, err}
	}()
	select {
	case a := <-ch:
		if a.err != nil {
			t.Fatal(a.err)
		}
		t.Cleanup(func() { a.c.Close() })
		return a.c
	case <-time.After(3 * time.Second):
		t.Fatal("Accept bloqué")
		return nil
	}
}

func readN(t *testing.T, c net.Conn, n int) string {
	t.Helper()
	c.SetReadDeadline(time.Now().Add(2 * time.Second)) //nolint:errcheck
	buf := make([]byte, n)
	if _, err := io.ReadFull(c, buf); err != nil {
		t.Fatalf("lecture : %v", err)
	}
	return string(buf)
}

func TestInbound_V1(t *testing.T) {
	l := listen(t, "127.0.0.1")
	c := send(t, l, []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\nGET / HTTP/1.1\r\n"))
	if got := c.RemoteAddr().String(); got != "203.0.113.7:51000" {
		t.Fatalf("RemoteAddr = %s", got)
	}
	if got := c.LocalAddr().String(); got != "10.0.0.1:443" {
		t.Fatalf("LocalAddr = %s", got)
	}
	if got := readN(t, c, 5); got != "GET /" {
		t.Fatalf("les données applicatives doivent suivre l'en-tête, lu %q", got)
	}
}

func TestInbound_V1Unknown(t *testing.T) {
	l := listen(t, "127.0.0.1")
	c := send(t, l, []byte("PROXY UNKNOWN\r\nhello"))
	if c.RemoteAddr().String() == "" || c.RemoteAddr().String()[:9] != "127.0.0.1" {
		t.Fatalf("UNKNOWN doit garder l'adresse réelle, obtenu %s", c.RemoteAddr())
	}
	if got := readN(t, c, 5); got != "hello" {
		t.Fatalf("lu %q", got)
	}
}

func TestInbound_V2RoundTrip(t *testing.T) {
	l := listen(t, "127.0.0.1")
	src := netip.MustParseAddrPort("198.51.100.9:40000")
	dst := netip.MustParseAddrPort("192.0.2.1:443")
	c := send(t, l, append(Header("v2", src, dst), []byte("data!")...))
	if got := c.RemoteAddr().String(); got != src.String() {
		t.Fatalf("RemoteAddr = %s", got)
	}
	if got := readN(t, c, 5); got != "data!" {
		t.Fatalf("lu %q", got)
	}
}

func TestInbound_V2IPv6(t *testing.T) {
	l := listen(t, "127.0.0.1")
	src := netip.MustParseAddrPort("[2001:db8::5]:40000")
	dst := netip.MustParseAddrPort("[2001:db8::1]:443")
	c := send(t, l, append(Header("v2", src, dst), []byte("x")...))
	if got := c.RemoteAddr().String(); got != src.String() {
		t.Fatalf("RemoteAddr = %s", got)
	}
}

func TestInbound_V2Local(t *testing.T) {
	l := listen(t, "127.0.0.1")
	mixed := Header("v2", netip.MustParseAddrPort("1.2.3.4:1"), netip.MustParseAddrPort("[::1]:2"))
	c := send(t, l, append(mixed, []byte("ok")...))
	if c.RemoteAddr().String()[:9] != "127.0.0.1" {
		t.Fatalf("LOCAL doit garder l'adresse réelle, obtenu %s", c.RemoteAddr())
	}
	if got := readN(t, c, 2); got != "ok" {
		t.Fatalf("lu %q", got)
	}
}

func TestInbound_UntrustedSourceCannotSpoof(t *testing.T) {
	l := listen(t, "10.99.0.0/16")
	payload := []byte("PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\nGET /")
	c := send(t, l, payload)
	if c.RemoteAddr().String()[:9] != "127.0.0.1" {
		t.Fatalf("une source non fiable a imposé son adresse : %s", c.RemoteAddr())
	}
	if got := readN(t, c, len(payload)); got != string(payload) {
		t.Fatalf("l'en-tête doit rester dans le flux d'une source non fiable, lu %q", got)
	}
}

func TestInbound_TrustedWithoutHeaderPassesThrough(t *testing.T) {
	l := listen(t, "127.0.0.1")
	c := send(t, l, []byte("GET / HTTP/1.1\r\n"))
	if got := readN(t, c, 3); got != "GET" {
		t.Fatalf("lu %q", got)
	}
	if c.RemoteAddr().String()[:9] != "127.0.0.1" {
		t.Fatalf("RemoteAddr = %s", c.RemoteAddr())
	}
}

func TestInbound_MalformedHeaderClosesConnection(t *testing.T) {
	l := listen(t, "127.0.0.1")
	c, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	c.Write([]byte("PROXY TCP4 not-an-ip 1.1.1.1 1 2\r\n")) //nolint:errcheck
	c.SetReadDeadline(time.Now().Add(2 * time.Second))       //nolint:errcheck
	if _, err := c.Read(make([]byte, 1)); err == nil {
		t.Fatal("la connexion aurait dû être fermée")
	}
}

func TestInbound_SlowHeaderDoesNotBlockAccept(t *testing.T) {
	l := listen(t, "127.0.0.1")
	slow, err := net.Dial("tcp", l.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	defer slow.Close()
	slow.Write([]byte("PRO")) //nolint:errcheck — jamais terminé

	// Peek(5) du premier client est bloqué ; un second client avec en-tête complet doit passer.
	c := send(t, l, []byte("PROXY TCP4 203.0.113.7 10.0.0.1 1 2\r\nZ"))
	if c.RemoteAddr().String() != "203.0.113.7:1" {
		t.Fatalf("RemoteAddr = %s", c.RemoteAddr())
	}
}

func TestHeaderV1Format(t *testing.T) {
	got := string(Header("v1", netip.MustParseAddrPort("203.0.113.7:51000"), netip.MustParseAddrPort("10.0.0.1:443")))
	if got != "PROXY TCP4 203.0.113.7 10.0.0.1 51000 443\r\n" {
		t.Fatalf("v1 = %q", got)
	}
	if got := string(Header("v1", netip.MustParseAddrPort("1.2.3.4:1"), netip.MustParseAddrPort("[::1]:2"))); got != "PROXY UNKNOWN\r\n" {
		t.Fatalf("familles mixtes = %q", got)
	}
	// Une IPv4 reçue sur une socket IPv6 (::ffff:a.b.c.d) est annoncée en TCP4.
	got = string(Header("v1", netip.MustParseAddrPort("[::ffff:203.0.113.7]:5"), netip.MustParseAddrPort("10.0.0.1:443")))
	if got != "PROXY TCP4 203.0.113.7 10.0.0.1 5 443\r\n" {
		t.Fatalf("v4-mappé = %q", got)
	}
}

func TestParseTrusted(t *testing.T) {
	p, err := ParseTrusted([]string{"10.0.0.0/8", " 192.168.1.5 ", "", "::1"})
	if err != nil || len(p) != 3 {
		t.Fatalf("p=%v err=%v", p, err)
	}
	if _, err := ParseTrusted([]string{"nope"}); err == nil {
		t.Fatal("entrée invalide acceptée")
	}
}
