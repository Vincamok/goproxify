// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package proxyproto implémente le PROXY protocol v1 (texte) et v2 (binaire) de HAProxy :
// lecture en entrée derrière un load balancer L4, écriture vers un backend.
package proxyproto

import (
	"bufio"
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"sync"
	"time"
)

var v2Sig = []byte("\r\n\r\n\x00\r\nQUIT\n")

const (
	v1MaxLen         = 107
	headerTimeout    = 5 * time.Second
	maxV2PayloadSize = 4096
)

// ParseTrusted convertit une liste de CIDR ou d'adresses IP en préfixes.
func ParseTrusted(entries []string) ([]netip.Prefix, error) {
	out := make([]netip.Prefix, 0, len(entries))
	for _, e := range entries {
		e = strings.TrimSpace(e)
		if e == "" {
			continue
		}
		if p, err := netip.ParsePrefix(e); err == nil {
			out = append(out, p.Masked())
			continue
		}
		a, err := netip.ParseAddr(e)
		if err != nil {
			return nil, fmt.Errorf("proxy_protocol : %q n'est ni un CIDR ni une adresse IP", e)
		}
		a = a.Unmap()
		out = append(out, netip.PrefixFrom(a, a.BitLen()))
	}
	return out, nil
}

func isTrusted(addr net.Addr, trusted []netip.Prefix) bool {
	ap, err := netip.ParseAddrPort(addr.String())
	if err != nil {
		return false
	}
	ip := ap.Addr().Unmap()
	for _, p := range trusted {
		if p.Contains(ip) {
			return true
		}
	}
	return false
}

// Conn expose l'adresse du client d'origine annoncée par le load balancer.
type Conn struct {
	net.Conn
	br     *bufio.Reader
	remote net.Addr
	local  net.Addr
}

func (c *Conn) Read(b []byte) (int, error) { return c.br.Read(b) }

func (c *Conn) RemoteAddr() net.Addr {
	if c.remote != nil {
		return c.remote
	}
	return c.Conn.RemoteAddr()
}

func (c *Conn) LocalAddr() net.Addr {
	if c.local != nil {
		return c.local
	}
	return c.Conn.LocalAddr()
}

type result struct {
	conn net.Conn
	err  error
}

// Listener lit l'en-tête PROXY des connexions venant d'une source de confiance.
// Une connexion d'une autre source n'est jamais interprétée (un client ne peut
// pas usurper son adresse) ; une source de confiance sans en-tête (sonde du load
// balancer par exemple) est servie avec son adresse réelle. L'en-tête est lu
// hors de la boucle Accept : un client lent ne bloque pas les suivants.
type Listener struct {
	inner   net.Listener
	trusted []netip.Prefix
	ch      chan result
	done    chan struct{}
	once    sync.Once
}

func NewListener(inner net.Listener, trusted []netip.Prefix) *Listener {
	l := &Listener{inner: inner, trusted: trusted, ch: make(chan result), done: make(chan struct{})}
	go l.loop()
	return l
}

func (l *Listener) deliver(r result) {
	select {
	case l.ch <- r:
	case <-l.done:
		if r.conn != nil {
			r.conn.Close()
		}
	}
}

func (l *Listener) loop() {
	for {
		c, err := l.inner.Accept()
		if err != nil {
			l.deliver(result{err: err})
			if errors.Is(err, net.ErrClosed) {
				return
			}
			select {
			case <-l.done:
				return
			default:
				continue
			}
		}
		if !isTrusted(c.RemoteAddr(), l.trusted) {
			l.deliver(result{conn: c})
			continue
		}
		go func() {
			pc, err := handshake(c)
			if err != nil {
				c.Close()
				return
			}
			l.deliver(result{conn: pc})
		}()
	}
}

func (l *Listener) Accept() (net.Conn, error) {
	select {
	case r := <-l.ch:
		return r.conn, r.err
	case <-l.done:
		return nil, net.ErrClosed
	}
}

func (l *Listener) Close() error {
	l.once.Do(func() { close(l.done) })
	return l.inner.Close()
}

func (l *Listener) Addr() net.Addr { return l.inner.Addr() }

func handshake(c net.Conn) (*Conn, error) {
	c.SetReadDeadline(time.Now().Add(headerTimeout)) //nolint:errcheck
	defer c.SetReadDeadline(time.Time{})              //nolint:errcheck

	br := bufio.NewReaderSize(c, 4096)
	pc := &Conn{Conn: c, br: br}
	head, err := br.Peek(5)
	if err != nil {
		return nil, err
	}
	switch {
	case string(head) == "PROXY":
		src, dst, err := readV1(br)
		if err != nil {
			return nil, err
		}
		pc.remote, pc.local = src, dst
	case bytes.Equal(head[:4], v2Sig[:4]) && head[4] == v2Sig[4]:
		src, dst, err := readV2(br)
		if err != nil {
			return nil, err
		}
		pc.remote, pc.local = src, dst
	}
	return pc, nil
}

func readV1(br *bufio.Reader) (src, dst net.Addr, err error) {
	var line []byte
	for len(line) < v1MaxLen {
		b, err := br.ReadByte()
		if err != nil {
			return nil, nil, err
		}
		line = append(line, b)
		if b == '\n' {
			break
		}
	}
	if !bytes.HasSuffix(line, []byte("\r\n")) {
		return nil, nil, errors.New("proxy protocol v1 : fin de ligne absente")
	}
	f := strings.Fields(string(line))
	if len(f) < 2 || f[0] != "PROXY" {
		return nil, nil, errors.New("proxy protocol v1 : en-tête invalide")
	}
	if f[1] == "UNKNOWN" {
		return nil, nil, nil
	}
	if len(f) != 6 || (f[1] != "TCP4" && f[1] != "TCP6") {
		return nil, nil, errors.New("proxy protocol v1 : champs invalides")
	}
	sa, err1 := netip.ParseAddr(f[2])
	da, err2 := netip.ParseAddr(f[3])
	sp, err3 := strconv.ParseUint(f[4], 10, 16)
	dp, err4 := strconv.ParseUint(f[5], 10, 16)
	if err1 != nil || err2 != nil || err3 != nil || err4 != nil {
		return nil, nil, errors.New("proxy protocol v1 : adresse invalide")
	}
	if (f[1] == "TCP4") != sa.Is4() || (f[1] == "TCP4") != da.Is4() {
		return nil, nil, errors.New("proxy protocol v1 : famille incohérente")
	}
	return tcpAddr(sa, sp), tcpAddr(da, dp), nil
}

func tcpAddr(a netip.Addr, port uint64) net.Addr {
	return net.TCPAddrFromAddrPort(netip.AddrPortFrom(a, uint16(port)))
}

func readV2(br *bufio.Reader) (src, dst net.Addr, err error) {
	hdr := make([]byte, 16)
	if _, err := io.ReadFull(br, hdr); err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(hdr[:12], v2Sig) {
		return nil, nil, errors.New("proxy protocol v2 : signature invalide")
	}
	if hdr[12]>>4 != 2 {
		return nil, nil, errors.New("proxy protocol v2 : version invalide")
	}
	n := int(binary.BigEndian.Uint16(hdr[14:16]))
	if n > maxV2PayloadSize {
		return nil, nil, errors.New("proxy protocol v2 : en-tête trop long")
	}
	payload := make([]byte, n)
	if _, err := io.ReadFull(br, payload); err != nil {
		return nil, nil, err
	}
	switch hdr[12] & 0x0F {
	case 0x0: // LOCAL : connexion propre du load balancer (sonde)
		return nil, nil, nil
	case 0x1: // PROXY
	default:
		return nil, nil, errors.New("proxy protocol v2 : commande inconnue")
	}
	switch hdr[13] {
	case 0x11: // TCP over IPv4
		if n < 12 {
			return nil, nil, errors.New("proxy protocol v2 : adresses IPv4 tronquées")
		}
		sa, _ := netip.AddrFromSlice(payload[0:4])
		da, _ := netip.AddrFromSlice(payload[4:8])
		return tcpAddr(sa, uint64(binary.BigEndian.Uint16(payload[8:10]))), tcpAddr(da, uint64(binary.BigEndian.Uint16(payload[10:12]))), nil
	case 0x21: // TCP over IPv6
		if n < 36 {
			return nil, nil, errors.New("proxy protocol v2 : adresses IPv6 tronquées")
		}
		sa, _ := netip.AddrFromSlice(payload[0:16])
		da, _ := netip.AddrFromSlice(payload[16:32])
		return tcpAddr(sa, uint64(binary.BigEndian.Uint16(payload[32:34]))), tcpAddr(da, uint64(binary.BigEndian.Uint16(payload[34:36]))), nil
	}
	// UDP, UNIX ou famille non spécifiée : on garde l'adresse réelle.
	return nil, nil, nil
}

// Header encode l'en-tête à écrire en tête d'une connexion vers un backend.
// version vaut "v1" ou "v2". Si src et dst ne sont pas de même famille IP, l'en-tête
// n'annonce pas d'adresse (UNKNOWN en v1, LOCAL en v2) plutôt qu'une adresse fausse.
func Header(version string, src, dst netip.AddrPort) []byte {
	src = netip.AddrPortFrom(src.Addr().Unmap(), src.Port())
	dst = netip.AddrPortFrom(dst.Addr().Unmap(), dst.Port())
	same := src.IsValid() && dst.IsValid() && src.Addr().Is4() == dst.Addr().Is4()

	if version == "v2" {
		out := append([]byte{}, v2Sig...)
		if !same {
			return append(out, 0x20, 0x00, 0x00, 0x00)
		}
		if src.Addr().Is4() {
			out = append(out, 0x21, 0x11, 0x00, 0x0C)
			s, d := src.Addr().As4(), dst.Addr().As4()
			out = append(out, s[:]...)
			out = append(out, d[:]...)
		} else {
			out = append(out, 0x21, 0x21, 0x00, 0x24)
			s, d := src.Addr().As16(), dst.Addr().As16()
			out = append(out, s[:]...)
			out = append(out, d[:]...)
		}
		return binary.BigEndian.AppendUint16(binary.BigEndian.AppendUint16(out, src.Port()), dst.Port())
	}

	if !same {
		return []byte("PROXY UNKNOWN\r\n")
	}
	proto := "TCP6"
	if src.Addr().Is4() {
		proto = "TCP4"
	}
	return []byte(fmt.Sprintf("PROXY %s %s %s %d %d\r\n", proto, src.Addr(), dst.Addr(), src.Port(), dst.Port()))
}

// ValidVersion indique si v est une version d'écriture reconnue ("" = désactivé).
func ValidVersion(v string) bool { return v == "" || v == "v1" || v == "v2" }

// AddrPort convertit une net.Addr TCP en netip.AddrPort (zéro si illisible).
func AddrPort(a net.Addr) netip.AddrPort {
	if a == nil {
		return netip.AddrPort{}
	}
	ap, _ := netip.ParseAddrPort(a.String())
	return ap
}
