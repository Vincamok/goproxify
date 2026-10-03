// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"net"
	"strings"
	"testing"

	xacme "golang.org/x/crypto/acme"

	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

func testClient(t *testing.T) *xacme.Client {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return &xacme.Client{Key: key}
}

func TestBuildEdgeChallenge_HTTP01(t *testing.T) {
	c := testClient(t)
	ch, err := buildEdgeChallenge(c, &xacme.Challenge{Token: "tok123"}, edgetls.ChallengeHTTP01, "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(ch.Response, "tok123.") {
		t.Fatalf("keyAuth = %q", ch.Response)
	}
	store := edgetls.NewChallengeStore()
	if err := store.Apply(ch); err != nil {
		t.Fatal(err)
	}
	if got, ok := store.HTTPResponse("tok123"); !ok || got != ch.Response {
		t.Fatalf("réponse servie = %q, %v", got, ok)
	}
}

// Le certificat généré côté Admin, posé sur la passerelle, est présenté à un client qui
// annonce l'ALPN acme-tls/1 — handshake TLS réel.
func TestBuildEdgeChallenge_TLSALPN01Handshake(t *testing.T) {
	c := testClient(t)
	ch, err := buildEdgeChallenge(c, &xacme.Challenge{Token: "tok123"}, edgetls.ChallengeTLSALPN01, "a.example.com")
	if err != nil {
		t.Fatal(err)
	}
	cs := edgetls.NewCertStore()
	if err := cs.Challenges.Apply(ch); err != nil {
		t.Fatal(err)
	}

	srvConn, cliConn := net.Pipe()
	defer srvConn.Close()
	defer cliConn.Close()
	srv := tls.Server(srvConn, &tls.Config{
		GetCertificate: cs.GetCertificate,
		NextProtos:     []string{"h2", "http/1.1", edgetls.ACMETLSALPNProto},
	})
	go srv.Handshake() //nolint:errcheck

	cli := tls.Client(cliConn, &tls.Config{
		ServerName:         "a.example.com",
		NextProtos:         []string{edgetls.ACMETLSALPNProto},
		InsecureSkipVerify: true, //nolint:gosec // le challenge est auto-signé par construction
	})
	if err := cli.Handshake(); err != nil {
		t.Fatal(err)
	}
	st := cli.ConnectionState()
	if st.NegotiatedProtocol != edgetls.ACMETLSALPNProto {
		t.Fatalf("ALPN négocié = %q", st.NegotiatedProtocol)
	}
	leaf := st.PeerCertificates[0]
	if len(leaf.DNSNames) != 1 || leaf.DNSNames[0] != "a.example.com" {
		t.Fatalf("SAN = %v", leaf.DNSNames)
	}
	found := false
	for _, e := range leaf.Extensions {
		if e.Id.String() == "1.3.6.1.5.5.7.1.31" && e.Critical {
			found = true
		}
	}
	if !found {
		t.Fatal("extension acmeIdentifier critique absente")
	}
}

func TestIsEdgeChallengeMethod(t *testing.T) {
	for m, want := range map[string]bool{MethodHTTP01: true, MethodTLSALPN01: true, MethodDNS01: false, "http": false, "manual": false, "": false} {
		if IsEdgeChallengeMethod(m) != want {
			t.Errorf("IsEdgeChallengeMethod(%q) != %v", m, want)
		}
	}
}

func TestObtainOnEdges_RefusesWildcard(t *testing.T) {
	m := &Manager{}
	err := m.obtainOnEdges(t.Context(), "*.example.com", edgetls.ChallengeHTTP01)
	if err == nil || !strings.Contains(err.Error(), "wildcard") {
		t.Fatalf("err = %v", err)
	}
}
