// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"io"
	"log/slog"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"golang.org/x/crypto/ocsp"
)

type ocspFixture struct {
	certPEM, keyPEM []byte
	ca              *x509.Certificate
	caKey           *ecdsa.PrivateKey
}

func newOCSPFixture(t *testing.T, ocspURL string) ocspFixture {
	t.Helper()
	caKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	caTpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test CA"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTpl, caTpl, &caKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	ca, _ := x509.ParseCertificate(caDER)

	leafKey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	leafTpl := &x509.Certificate{
		SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: "a.example.com"},
		DNSNames:  []string{"a.example.com"},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(12 * time.Hour),
		OCSPServer: ocspServers(ocspURL),
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTpl, ca, &leafKey.PublicKey, caKey)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalPKCS8PrivateKey(leafKey)
	chain := append(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})...)
	return ocspFixture{
		certPEM: chain, keyPEM: pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		ca: ca, caKey: caKey,
	}
}

// ocspResponder répond avec la CA de f (renseignée après démarrage : l'URL du répondeur est
// gravée dans le certificat, donc le serveur démarre avant la fixture).
func ocspResponder(f *ocspFixture, status *int) *httptest.Server {
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		req, err := ocsp.ParseRequest(body)
		if err != nil {
			http.Error(w, err.Error(), 400)
			return
		}
		resp, err := ocsp.CreateResponse(f.ca, f.ca, ocsp.Response{
			Status: *status, SerialNumber: req.SerialNumber,
			ThisUpdate: time.Now().Add(-time.Minute), NextUpdate: time.Now().Add(4 * time.Hour),
			RevokedAt: time.Now().Add(-time.Minute),
		}, f.caKey)
		if err != nil {
			http.Error(w, err.Error(), 500)
			return
		}
		w.Header().Set("Content-Type", "application/ocsp-response")
		w.Write(resp) //nolint:errcheck
	}))
}

func stapleOf(t *testing.T, cs *CertStore) []byte {
	t.Helper()
	c, err := cs.GetCertificate(&tls.ClientHelloInfo{ServerName: "a.example.com"})
	if err != nil {
		t.Fatal(err)
	}
	return c.OCSPStaple
}

func setup(t *testing.T, st int) (*CertStore, *OCSPStapler, ocspFixture) {
	t.Helper()
	var f ocspFixture
	status := st
	rsp := ocspResponder(&f, &status)
	t.Cleanup(rsp.Close)
	f = newOCSPFixture(t, rsp.URL)
	cs := NewCertStore()
	if err := cs.StorePEM("a.example.com", f.certPEM, f.keyPEM); err != nil {
		t.Fatal(err)
	}
	return cs, NewOCSPStapler(cs, slog.New(slog.NewTextHandler(io.Discard, nil))), f
}

func TestOCSPStapler_Staples(t *testing.T) {
	t.Setenv("GPX_OCSP_ALLOW_PRIVATE", "1")
	cs, st, f := setup(t, ocsp.Good)
	var got map[string]OCSPStatus
	st.OnUpdate = func(m map[string]OCSPStatus) { got = m }
	st.RefreshAll(context.Background())

	staple := stapleOf(t, cs)
	if len(staple) == 0 {
		t.Fatal("aucune agrafe")
	}
	leaf, _ := x509.ParseCertificate(mustDER(t, f.certPEM))
	parsed, err := ocsp.ParseResponseForCert(staple, leaf, f.ca)
	if err != nil || parsed.Status != ocsp.Good {
		t.Fatalf("agrafe invalide : %v", err)
	}
	if s := got["a.example.com"]; s.Revoked || s.NextUpdate.IsZero() {
		t.Fatalf("statut = %+v", s)
	}

	// Même certificat re-poussé : l'agrafe est conservée.
	if err := cs.StorePEM("a.example.com", f.certPEM, f.keyPEM); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(stapleOf(t, cs), staple) {
		t.Fatal("agrafe perdue au re-push du même certificat")
	}
}

func TestOCSPStapler_Revoked(t *testing.T) {
	t.Setenv("GPX_OCSP_ALLOW_PRIVATE", "1")
	cs, st, _ := setup(t, ocsp.Revoked)
	var got map[string]OCSPStatus
	st.OnUpdate = func(m map[string]OCSPStatus) { got = m }
	st.RefreshAll(context.Background())
	if len(stapleOf(t, cs)) == 0 || !got["a.example.com"].Revoked {
		t.Fatalf("révocation non agrafée/signalée : %+v", got)
	}
}

func TestOCSPStapler_BlocksPrivateResponder(t *testing.T) {
	cs, st, _ := setup(t, ocsp.Good) // sans GPX_OCSP_ALLOW_PRIVATE : 127.0.0.1 refusé
	st.RefreshAll(context.Background())
	if len(stapleOf(t, cs)) != 0 {
		t.Fatal("OCSP récupéré depuis une adresse privée")
	}
}

func TestOCSPStapler_SkipsCertWithoutOCSPURL(t *testing.T) {
	f := newOCSPFixture(t, "")
	cs := NewCertStore()
	if err := cs.StorePEM("a.example.com", f.certPEM, f.keyPEM); err != nil {
		t.Fatal(err)
	}
	NewOCSPStapler(cs, slog.New(slog.NewTextHandler(io.Discard, nil))).RefreshAll(context.Background())
	if len(stapleOf(t, cs)) != 0 {
		t.Fatal("agrafe sans URL OCSP")
	}
}

func mustDER(t *testing.T, chainPEM []byte) []byte {
	t.Helper()
	b, _ := pem.Decode(chainPEM)
	return b.Bytes
}

func ocspServers(u string) []string {
	if u == "" {
		return nil
	}
	return []string{u}
}
