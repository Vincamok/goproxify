// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"crypto/tls"
	"fmt"
	"strings"
	"sync"
	"time"
)

const (
	ChallengeHTTP01    = "http-01"
	ChallengeTLSALPN01 = "tls-alpn-01"

	// ACMETLSALPNProto est le protocole ALPN réservé au challenge tls-alpn-01 (RFC 8737).
	ACMETLSALPNProto = "acme-tls/1"
	// ACMEHTTPPathPrefix est le préfixe des URL du challenge http-01 (RFC 8555 §8.3).
	ACMEHTTPPathPrefix = "/.well-known/acme-challenge/"

	challengeTTL = 15 * time.Minute
)

// ACMEChallenge est le message Admin → passerelle qui pose (ou retire) la réponse à un
// challenge ACME. Seule la passerelle qui reçoit le trafic public du domaine peut y répondre.
type ACMEChallenge struct {
	Type   string `json:"type"`
	Domain string `json:"domain"`
	Clear  bool   `json:"clear,omitempty"`
	// http-01 : l'URL /.well-known/acme-challenge/<Token> répond Response.
	Token    string `json:"token,omitempty"`
	Response string `json:"response,omitempty"`
	// tls-alpn-01 : certificat auto-signé portant l'extension acmeIdentifier, servi quand
	// le client annonce l'ALPN acme-tls/1.
	CertPEM []byte `json:"cert_pem,omitempty"`
	KeyPEM  []byte `json:"key_pem,omitempty"`
}

type httpChallenge struct {
	response string
	expires  time.Time
}

type alpnChallenge struct {
	cert    *tls.Certificate
	expires time.Time
}

// ChallengeStore garde en RAM les réponses aux challenges ACME en cours. Elles sont
// transitoires (le temps d'une émission) : rien n'est persisté ni repris au redémarrage.
type ChallengeStore struct {
	mu   sync.Mutex
	http map[string]httpChallenge
	alpn map[string]alpnChallenge
	now  func() time.Time
}

func NewChallengeStore() *ChallengeStore {
	return &ChallengeStore{
		http: make(map[string]httpChallenge),
		alpn: make(map[string]alpnChallenge),
		now:  time.Now,
	}
}

// Apply pose ou retire un challenge selon ch.Clear.
func (s *ChallengeStore) Apply(ch ACMEChallenge) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.purgeLocked()
	switch ch.Type {
	case ChallengeHTTP01:
		if ch.Token == "" {
			return fmt.Errorf("challenge http-01 sans token")
		}
		if ch.Clear {
			delete(s.http, ch.Token)
			return nil
		}
		s.http[ch.Token] = httpChallenge{response: ch.Response, expires: s.now().Add(challengeTTL)}
	case ChallengeTLSALPN01:
		domain := strings.ToLower(ch.Domain)
		if domain == "" {
			return fmt.Errorf("challenge tls-alpn-01 sans domaine")
		}
		if ch.Clear {
			delete(s.alpn, domain)
			return nil
		}
		cert, err := tls.X509KeyPair(ch.CertPEM, ch.KeyPEM)
		if err != nil {
			return fmt.Errorf("certificat tls-alpn-01 invalide : %w", err)
		}
		s.alpn[domain] = alpnChallenge{cert: &cert, expires: s.now().Add(challengeTTL)}
	default:
		return fmt.Errorf("type de challenge inconnu %q", ch.Type)
	}
	return nil
}

// HTTPResponse retourne le contenu à servir pour un token http-01.
func (s *ChallengeStore) HTTPResponse(token string) (string, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.http[token]
	if !ok || !c.expires.After(s.now()) {
		return "", false
	}
	return c.response, true
}

// ALPNCert retourne le certificat de challenge pour le SNI donné.
func (s *ChallengeStore) ALPNCert(sni string) (*tls.Certificate, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	c, ok := s.alpn[strings.ToLower(sni)]
	if !ok || !c.expires.After(s.now()) {
		return nil, false
	}
	return c.cert, true
}

func (s *ChallengeStore) purgeLocked() {
	now := s.now()
	for k, c := range s.http {
		if !c.expires.After(now) {
			delete(s.http, k)
		}
	}
	for k, c := range s.alpn {
		if !c.expires.After(now) {
			delete(s.alpn, k)
		}
	}
}

func wantsACMEALPN(hello *tls.ClientHelloInfo) bool {
	for _, p := range hello.SupportedProtos {
		if p == ACMETLSALPNProto {
			return true
		}
	}
	return false
}
