// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"context"
	"crypto/x509"
	"database/sql"
	"encoding/pem"
	"fmt"
	"strings"
	"time"

	xacme "golang.org/x/crypto/acme"

	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

// Méthodes de validation d'un domaine (colonne domains.cert_method). Les valeurs « http » et
// « manual » historiques ne déclenchent aucune émission ACME ; seules ces trois le font.
const (
	MethodDNS01     = "dns"
	MethodHTTP01    = "acme-http"
	MethodTLSALPN01 = "acme-tls-alpn"
)

// challengeSettle laisse le temps à la WS de livrer le challenge avant que l'AC ne valide :
// le push passerelle n'a pas d'accusé de réception.
const challengeSettle = 3 * time.Second

// ChallengePusher pose et retire les réponses http-01 / tls-alpn-01 sur les passerelles.
// Retourne le nombre de passerelles atteintes.
type ChallengePusher interface {
	PushACMEChallenge(ctx context.Context, ch edgetls.ACMEChallenge) int
}

// IsEdgeChallengeMethod indique si la méthode se valide par la passerelle (hors DNS).
func IsEdgeChallengeMethod(method string) bool {
	return method == MethodHTTP01 || method == MethodTLSALPN01
}

// ObtainCertForMethod émet un certificat selon la méthode du domaine ; dnsProviderType et
// credentials ne servent qu'à DNS-01.
func (m *Manager) ObtainCertForMethod(ctx context.Context, domain, method, dnsProviderType string, credentials map[string]any) error {
	switch method {
	case MethodHTTP01:
		return m.obtainOnEdges(ctx, domain, edgetls.ChallengeHTTP01)
	case MethodTLSALPN01:
		return m.obtainOnEdges(ctx, domain, edgetls.ChallengeTLSALPN01)
	default:
		return m.ObtainCertWithProvider(ctx, domain, dnsProviderType, credentials)
	}
}

func (m *Manager) obtainOnEdges(ctx context.Context, domain, typ string) error {
	if strings.HasPrefix(strings.TrimSpace(domain), "*.") {
		return fmt.Errorf("acme: un certificat wildcard exige DNS-01 (%s impossible)", typ)
	}
	cp, ok := m.pusher.(ChallengePusher)
	if !ok {
		return fmt.Errorf("acme: aucune passerelle joignable pour %s", typ)
	}
	return m.obtainCert(ctx, domain, func(ctx context.Context, client *xacme.Client, authURLs []string) error {
		return m.fulfillOnEdges(ctx, client, authURLs, typ, cp)
	})
}

// fulfillOnEdges pose les réponses sur les passerelles, déclenche la validation puis nettoie.
func (m *Manager) fulfillOnEdges(ctx context.Context, client *xacme.Client, authURLs []string, typ string, cp ChallengePusher) error {
	type pending struct {
		authURL string
		chal    *xacme.Challenge
	}
	var todo []pending
	var posted []edgetls.ACMEChallenge
	defer func() {
		for _, ch := range posted {
			ch.Clear = true
			cp.PushACMEChallenge(context.WithoutCancel(ctx), ch)
		}
	}()

	for _, authURL := range authURLs {
		auth, err := client.GetAuthorization(ctx, authURL)
		if err != nil {
			return fmt.Errorf("acme: get auth : %w", err)
		}
		if auth.Status == xacme.StatusValid {
			continue
		}
		if auth.Wildcard {
			return fmt.Errorf("acme: %s ne valide pas un wildcard (%s)", typ, auth.Identifier.Value)
		}
		var chal *xacme.Challenge
		for _, c := range auth.Challenges {
			if c.Type == typ {
				chal = c
				break
			}
		}
		if chal == nil {
			return fmt.Errorf("acme: pas de challenge %s pour %s", typ, auth.Identifier.Value)
		}
		ch, err := buildEdgeChallenge(client, chal, typ, auth.Identifier.Value)
		if err != nil {
			return err
		}
		posted = append(posted, ch)
		if cp.PushACMEChallenge(ctx, ch) == 0 {
			return fmt.Errorf("acme: aucune passerelle connectée ne couvre %s", auth.Identifier.Value)
		}
		todo = append(todo, pending{authURL: authURL, chal: chal})
	}
	if len(todo) == 0 {
		return nil
	}

	select {
	case <-time.After(challengeSettle):
	case <-ctx.Done():
		return ctx.Err()
	}
	for _, p := range todo {
		if _, err := client.Accept(ctx, p.chal); err != nil {
			return fmt.Errorf("acme: accept challenge : %w", err)
		}
	}
	for _, p := range todo {
		if _, err := client.WaitAuthorization(ctx, p.authURL); err != nil {
			return fmt.Errorf("acme: wait auth : %w", err)
		}
	}
	return nil
}

func buildEdgeChallenge(client *xacme.Client, chal *xacme.Challenge, typ, domain string) (edgetls.ACMEChallenge, error) {
	ch := edgetls.ACMEChallenge{Type: typ, Domain: domain, Token: chal.Token}
	switch typ {
	case edgetls.ChallengeHTTP01:
		resp, err := client.HTTP01ChallengeResponse(chal.Token)
		if err != nil {
			return ch, fmt.Errorf("acme: calcul keyAuth : %w", err)
		}
		ch.Response = resp
	case edgetls.ChallengeTLSALPN01:
		cert, err := client.TLSALPN01ChallengeCert(chal.Token, domain)
		if err != nil {
			return ch, fmt.Errorf("acme: certificat tls-alpn-01 : %w", err)
		}
		keyDER, err := x509.MarshalPKCS8PrivateKey(cert.PrivateKey)
		if err != nil {
			return ch, fmt.Errorf("acme: clé tls-alpn-01 : %w", err)
		}
		ch.CertPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: cert.Certificate[0]})
		ch.KeyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	}
	return ch, nil
}

// renewCert renouvelle un certificat avec la méthode enregistrée pour son domaine.
// Sans ligne domaine (cert importé, restauré depuis disque…), DNS-01 avec le fournisseur par défaut.
func (m *Manager) renewCert(ctx context.Context, domain string) error {
	var method, dnsProvider string
	err := m.db.QueryRowContext(ctx,
		`SELECT cert_method, dns_provider FROM domains WHERE domain=?`, domain).Scan(&method, &dnsProvider)
	if err != nil && err != sql.ErrNoRows {
		m.log.Warn("acme: lecture méthode du domaine", "domain", domain, "err", err)
	}
	if IsEdgeChallengeMethod(method) {
		return m.ObtainCertForMethod(ctx, domain, method, "", nil)
	}
	return m.ObtainCert(ctx, domain)
}
