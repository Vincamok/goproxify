// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/tls"
	"testing"
	"time"
)

func TestChallengeStore_HTTP01(t *testing.T) {
	s := NewChallengeStore()
	if err := s.Apply(ACMEChallenge{Type: ChallengeHTTP01, Token: "tok", Response: "tok.thumb"}); err != nil {
		t.Fatal(err)
	}
	if got, ok := s.HTTPResponse("tok"); !ok || got != "tok.thumb" {
		t.Fatalf("réponse = %q, %v", got, ok)
	}
	if _, ok := s.HTTPResponse("autre"); ok {
		t.Fatal("token inconnu servi")
	}
	if err := s.Apply(ACMEChallenge{Type: ChallengeHTTP01, Token: "tok", Clear: true}); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.HTTPResponse("tok"); ok {
		t.Fatal("token servi après Clear")
	}
}

func TestChallengeStore_Expiry(t *testing.T) {
	s := NewChallengeStore()
	now := time.Now()
	s.now = func() time.Time { return now }
	s.Apply(ACMEChallenge{Type: ChallengeHTTP01, Token: "tok", Response: "x"}) //nolint:errcheck
	s.now = func() time.Time { return now.Add(challengeTTL + time.Second) }
	if _, ok := s.HTTPResponse("tok"); ok {
		t.Fatal("challenge expiré encore servi")
	}
}

func TestChallengeStore_Invalid(t *testing.T) {
	s := NewChallengeStore()
	for _, ch := range []ACMEChallenge{
		{Type: "dns-01", Token: "t"},
		{Type: ChallengeHTTP01},
		{Type: ChallengeTLSALPN01},
		{Type: ChallengeTLSALPN01, Domain: "a.example.com", CertPEM: []byte("x"), KeyPEM: []byte("y")},
	} {
		if err := s.Apply(ch); err == nil {
			t.Errorf("challenge %+v accepté", ch)
		}
	}
}

func TestGetCertificate_ACMEALPNIgnoredWithoutChallenge(t *testing.T) {
	cs := NewCertStore()
	hello := &tls.ClientHelloInfo{ServerName: "a.example.com", SupportedProtos: []string{ACMETLSALPNProto}}
	if _, err := cs.GetCertificate(hello); err == nil {
		t.Fatal("certificat servi sans challenge ALPN posé")
	}
}
