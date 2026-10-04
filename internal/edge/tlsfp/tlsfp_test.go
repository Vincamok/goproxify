// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tlsfp

import (
	"context"
	"crypto/md5" //nolint:gosec
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"net"
	"strings"
	"testing"
)

// helloBuilder assemble un ClientHello dans un enregistrement TLS.
type helloBuilder struct {
	legacy  uint16
	ciphers []uint16
	exts    [][]byte // chaque extension encodée (type + longueur + données)
}

func u16(v uint16) []byte { return []byte{byte(v >> 8), byte(v)} }

func ext(typ uint16, data []byte) []byte {
	return append(append(u16(typ), u16(uint16(len(data)))...), data...)
}

func (h helloBuilder) record() []byte {
	body := u16(h.legacy)
	body = append(body, make([]byte, 32)...)
	body = append(body, 0) // session id vide
	cs := []byte{}
	for _, c := range h.ciphers {
		cs = append(cs, u16(c)...)
	}
	body = append(body, u16(uint16(len(cs)))...)
	body = append(body, cs...)
	body = append(body, 1, 0) // compression null
	var exts []byte
	for _, e := range h.exts {
		exts = append(exts, e...)
	}
	body = append(body, u16(uint16(len(exts)))...)
	body = append(body, exts...)

	hs := append([]byte{0x01, byte(len(body) >> 16), byte(len(body) >> 8), byte(len(body))}, body...)
	return append([]byte{0x16, 0x03, 0x01, byte(len(hs) >> 8), byte(len(hs))}, hs...)
}

func listU16(vals ...uint16) []byte {
	var b []byte
	for _, v := range vals {
		b = append(b, u16(v)...)
	}
	return append(u16(uint16(len(b))), b...)
}

func alpn(protos ...string) []byte {
	var b []byte
	for _, p := range protos {
		b = append(append(b, byte(len(p))), p...)
	}
	return append(u16(uint16(len(b))), b...)
}

func sum12(s string) string {
	h := sha256.Sum256([]byte(s))
	return hex.EncodeToString(h[:])[:12]
}

func TestParse_JA3AndJA4OnSyntheticHello(t *testing.T) {
	h := helloBuilder{
		legacy:  0x0303,
		ciphers: []uint16{0x0a0a /* GREASE */, 0x1302, 0x1301, 0xc02b},
		exts: [][]byte{
			ext(0x2a2a, nil), // GREASE
			ext(0x0000, append(u16(8), []byte{0, 0, 5, 'a', '.', 't', 'e', 's'}...)),
			ext(0x000a, listU16(0xdada /* GREASE */, 29, 23)),
			ext(0x000b, []byte{1, 0}),
			ext(0x000d, listU16(0x0403, 0x0804)),
			ext(0x0010, alpn("h2", "http/1.1")),
			ext(0x002b, append([]byte{6}, listU16Bare(0x7a7a, 0x0304, 0x0303)...)),
		},
	}
	fp := Parse(h.record())
	if fp == nil {
		t.Fatal("ClientHello non reconnu")
	}

	wantJA3 := "771,4866-4865-49195,0-10-11-13-16-43,29-23,0"
	if fp.JA3 != wantJA3 {
		t.Fatalf("JA3 = %q, attendu %q", fp.JA3, wantJA3)
	}
	m := md5.Sum([]byte(wantJA3)) //nolint:gosec
	if fp.JA3Hash != hex.EncodeToString(m[:]) {
		t.Fatalf("JA3Hash = %s", fp.JA3Hash)
	}

	// JA4 : TLS 1.3 (supported_versions), SNI, 3 chiffrements, 6 extensions, ALPN h2.
	want := "t13d0306h2_" + sum12("1301,1302,c02b") + "_" + sum12("000a,000b,000d,002b_0403,0804")
	if fp.JA4 != want {
		t.Fatalf("JA4 = %s, attendu %s", fp.JA4, want)
	}
}

func listU16Bare(vals ...uint16) []byte {
	var b []byte
	for _, v := range vals {
		b = append(b, u16(v)...)
	}
	return b
}

func TestParse_NoSNINoALPNNoExtensions(t *testing.T) {
	fp := Parse(helloBuilder{legacy: 0x0303, ciphers: []uint16{0x002f}}.record())
	if fp == nil {
		t.Fatal("nil")
	}
	if want := "t12i010000_" + sum12("002f") + "_000000000000"; fp.JA4 != want {
		t.Fatalf("JA4 = %s, attendu %s", fp.JA4, want)
	}
	if fp.JA3 != "771,47,,," {
		t.Fatalf("JA3 = %q", fp.JA3)
	}
}

func TestParse_RejectsGarbage(t *testing.T) {
	for _, in := range [][]byte{nil, {0x17, 3, 3, 0, 1, 0}, []byte("GET / HTTP/1.1\r\n\r\n"), helloBuilder{legacy: 0x0303}.record()[:20]} {
		if Parse(in) != nil {
			t.Errorf("%q accepté", in)
		}
	}
	// Longueurs d'extension mensongères : pas de panique.
	rec := helloBuilder{legacy: 0x0303, ciphers: []uint16{1}, exts: [][]byte{{0x00, 0x10, 0xff, 0xff, 1}}}.record()
	_ = Parse(rec)
}

func TestParse_RealGoClientHello(t *testing.T) {
	client, server := net.Pipe()
	defer server.Close()
	go func() {
		c := tls.Client(client, &tls.Config{ServerName: "example.test", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}) //nolint:gosec
		_ = c.Handshake()
	}()
	buf := make([]byte, 0, 4096)
	tmp := make([]byte, 4096)
	for {
		n, err := server.Read(tmp)
		buf = append(buf, tmp[:n]...)
		if err != nil || (len(buf) >= 5 && len(buf) >= 5+int(buf[3])<<8|int(buf[4])) {
			break
		}
	}
	fp := Parse(buf)
	if fp == nil {
		t.Fatal("ClientHello Go non reconnu")
	}
	if !strings.HasPrefix(fp.JA4, "t13d") || !strings.Contains(fp.JA4[:10], "h2") {
		t.Fatalf("JA4 inattendu pour un client Go TLS 1.3 + h2 : %s", fp.JA4)
	}
	if len(fp.JA3Hash) != 32 || strings.Count(fp.JA4, "_") != 2 {
		t.Fatalf("format : %+v", fp)
	}
	// Deux clients Go identiques ont la même empreinte (aucun élément aléatoire ne doit y entrer).
	client2, server2 := net.Pipe()
	defer server2.Close()
	go func() {
		c := tls.Client(client2, &tls.Config{ServerName: "other.test", NextProtos: []string{"h2", "http/1.1"}, InsecureSkipVerify: true}) //nolint:gosec
		_ = c.Handshake()
	}()
	buf2 := make([]byte, 0, 4096)
	for {
		n, err := server2.Read(tmp)
		buf2 = append(buf2, tmp[:n]...)
		if err != nil || (len(buf2) >= 5 && len(buf2) >= 5+int(buf2[3])<<8|int(buf2[4])) {
			break
		}
	}
	if fp2 := Parse(buf2); fp2 == nil || fp2.JA4 != fp.JA4 || fp2.JA3Hash != fp.JA3Hash {
		t.Fatalf("empreinte instable entre deux handshakes : %v / %v", fp, fp2)
	}
}

func TestMatchesAndContext(t *testing.T) {
	fp := &Fingerprint{JA3Hash: "abc123", JA4: "t13d0306h2_aaa_bbb"}
	if !fp.Matches(map[string]struct{}{"abc123": {}}) || !fp.Matches(map[string]struct{}{"t13d0306h2_aaa_bbb": {}}) {
		t.Fatal("correspondance attendue")
	}
	if fp.Matches(map[string]struct{}{"zzz": {}}) || fp.Matches(nil) || (*Fingerprint)(nil).Matches(map[string]struct{}{"abc123": {}}) {
		t.Fatal("fausse correspondance")
	}
	if got := FromContext(WithContext(context.Background(), fp)); got != fp {
		t.Fatal("contexte")
	}
	if FromContext(context.Background()) != nil {
		t.Fatal("contexte vide")
	}
}

func TestIsGrease(t *testing.T) {
	for _, v := range []uint16{0x0a0a, 0x1a1a, 0xdada, 0xfafa} {
		if !isGrease(v) {
			t.Errorf("%04x devrait être GREASE", v)
		}
	}
	for _, v := range []uint16{0x0a1a, 0x1301, 0x0000, 0xc02b} {
		if isGrease(v) {
			t.Errorf("%04x n'est pas GREASE", v)
		}
	}
}
