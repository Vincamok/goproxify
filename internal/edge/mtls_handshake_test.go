// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

type testCA struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
	pem  string
}

func newTestCA(t *testing.T, cn string) *testCA {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(24 * time.Hour),
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	cert, _ := x509.ParseCertificate(der)
	return &testCA{cert: cert, key: key, pem: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}
}

func (ca *testCA) issue(t *testing.T, cn string, eku x509.ExtKeyUsage, notBefore, notAfter time.Time) tls.Certificate {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(time.Now().UnixNano()), Subject: pkix.Name{CommonName: cn}, DNSNames: []string{cn},
		NotBefore: notBefore, NotAfter: notAfter, KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{eku},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, ca.cert, &key.PublicKey, ca.key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

func mtlsListener(t *testing.T, routes ...*router.Route) (*sniListener, *tls.Config) {
	t.Helper()
	srvCA := newTestCA(t, "serveur")
	srvCert := srvCA.issue(t, "mtls.test", x509.ExtKeyUsageServerAuth, time.Now().Add(-time.Hour), time.Now().Add(time.Hour))
	base := &tls.Config{Certificates: []tls.Certificate{srvCert}, MinVersion: tls.VersionTLS12}
	tab := &router.Table{}
	if err := tab.Replace(routes); err != nil {
		t.Fatal(err)
	}
	return &sniListener{table: tab, log: testEdgeServer().log.Logger()}, base
}

func TestTLSConfigForMTLSRoutes(t *testing.T) {
	ca := newTestCA(t, "ca-test")
	l, base := mtlsListener(t,
		&router.Route{ID: "req", Host: "req.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertPEM: ca.pem, RequireClientCert: true}},
		&router.Route{ID: "opt", Host: "opt.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertPEM: ca.pem}},
		&router.Route{ID: "off", Host: "off.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: false, CACertPEM: ca.pem, RequireClientCert: true}},
		&router.Route{ID: "plain", Host: "plain.test", Type: router.RouteHTTP, TLSEnabled: true},
		&router.Route{ID: "bad", Host: "bad.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertFile: "/inexistant/ca.pem", RequireClientCert: true}},
		&router.Route{ID: "badopt", Host: "badopt.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertFile: "/inexistant/ca.pem"}},
	)

	cfg, ok := l.tlsConfigFor("req.test", base)
	if !ok || cfg.ClientAuth != tls.RequireAndVerifyClientCert || cfg.ClientCAs == nil {
		t.Fatalf("route qui exige un certificat client : ok=%v ClientAuth=%v CAs=%v", ok, cfg.ClientAuth, cfg.ClientCAs != nil)
	}
	if base.ClientAuth != tls.NoClientCert || base.ClientCAs != nil {
		t.Fatal("la configuration de base partagée ne doit jamais être modifiée")
	}
	if cfg, ok = l.tlsConfigFor("opt.test", base); !ok || cfg.ClientAuth != tls.RequestClientCert {
		t.Fatalf("route à certificat facultatif : ok=%v ClientAuth=%v", ok, cfg.ClientAuth)
	}
	for _, host := range []string{"off.test", "plain.test", "inconnu.test"} {
		if cfg, ok = l.tlsConfigFor(host, base); !ok || cfg != base {
			t.Errorf("%s : pas de demande de certificat client attendue (ok=%v)", host, ok)
		}
	}
	if _, ok = l.tlsConfigFor("bad.test", base); ok {
		t.Error("CA illisible sur une route qui exige un certificat : la connexion doit être refusée, pas servie sans vérification")
	}
	if cfg, ok = l.tlsConfigFor("badopt.test", base); !ok || cfg != base {
		t.Error("CA illisible sur une route à certificat facultatif : connexion servie sans demande de certificat")
	}
}

// handshake joue une vraie poignée de main TLS entre le serveur configuré pour la route et un client muni (ou non) d'un certificat.
func handshake(t *testing.T, cfg *tls.Config, client ...tls.Certificate) (certs int, err error) {
	t.Helper()
	c1, c2 := net.Pipe()
	defer c1.Close()
	defer c2.Close()
	_ = c1.SetDeadline(time.Now().Add(5 * time.Second))
	_ = c2.SetDeadline(time.Now().Add(5 * time.Second))
	go func() {
		cl := tls.Client(c1, &tls.Config{ServerName: "mtls.test", InsecureSkipVerify: true, Certificates: client}) //nolint:gosec // certificat de test
		_ = cl.Handshake()
		_, _ = cl.Read(make([]byte, 1)) // laisse passer l'alerte éventuelle (TLS 1.3 : le client termine avant la vérification du serveur)
	}()
	srv := tls.Server(c2, cfg)
	if err = srv.Handshake(); err != nil {
		return 0, err
	}
	return len(srv.ConnectionState().PeerCertificates), nil
}

func TestMTLSHandshakePerRoute(t *testing.T) {
	ca, rogue := newTestCA(t, "ca-test"), newTestCA(t, "ca-pirate")
	now := time.Now()
	valid := ca.issue(t, "client", x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour))
	wrongCA := rogue.issue(t, "client", x509.ExtKeyUsageClientAuth, now.Add(-time.Hour), now.Add(time.Hour))
	serverUse := ca.issue(t, "client", x509.ExtKeyUsageServerAuth, now.Add(-time.Hour), now.Add(time.Hour))
	expired := ca.issue(t, "client", x509.ExtKeyUsageClientAuth, now.Add(-48*time.Hour), now.Add(-24*time.Hour))

	l, base := mtlsListener(t,
		&router.Route{ID: "req", Host: "req.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertPEM: ca.pem, RequireClientCert: true}},
		&router.Route{ID: "opt", Host: "opt.test", Type: router.RouteHTTP, TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertPEM: ca.pem}},
	)
	req, _ := l.tlsConfigFor("req.test", base)
	opt, _ := l.tlsConfigFor("opt.test", base)

	if n, err := handshake(t, req, valid); err != nil || n != 1 {
		t.Fatalf("certificat client valide : certificats=%d err=%v", n, err)
	}
	for name, cert := range map[string]tls.Certificate{"autre autorité": wrongCA, "usage serverAuth seul": serverUse, "expiré": expired} {
		if _, err := handshake(t, req, cert); err == nil {
			t.Errorf("route exigeante, certificat %s : la poignée de main doit échouer", name)
		}
	}
	if _, err := handshake(t, req); err == nil {
		t.Error("route exigeante sans certificat client : la poignée de main doit échouer")
	}
	if n, err := handshake(t, opt); err != nil || n != 0 {
		t.Errorf("route facultative sans certificat : certificats=%d err=%v (attendu une connexion sans certificat)", n, err)
	}
	if n, err := handshake(t, opt, valid); err != nil || n != 1 {
		t.Errorf("route facultative avec un certificat : certificats=%d err=%v (le certificat doit être lu)", n, err)
	}
}
