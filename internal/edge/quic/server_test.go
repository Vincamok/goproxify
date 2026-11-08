// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package quic

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net"
	"net/http"
	"testing"
	"time"

	"github.com/quic-go/quic-go"
	"github.com/quic-go/quic-go/http3"
	"github.com/vincamok/goproxify/internal/config"
	edgetls "github.com/vincamok/goproxify/internal/edge/tls"
)

func selfSigned(t *testing.T, host string) (certPEM, keyPEM []byte) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: host}, DNSNames: []string{host},
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
		KeyUsage: x509.KeyUsageDigitalSignature, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb})
}

func freeUDPPort(t *testing.T) int {
	t.Helper()
	pc, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer pc.Close()
	return pc.LocalAddr().(*net.UDPAddr).Port
}

func get(t *testing.T, port int, host string) (*http.Response, string) {
	t.Helper()
	tr := &http3.Transport{
		TLSClientConfig: &tls.Config{ServerName: host, InsecureSkipVerify: true, NextProtos: []string{"h3"}}, //nolint:gosec // certificat de test
		Dial: func(ctx context.Context, _ string, cfg *tls.Config, qc *quic.Config) (*quic.Conn, error) {
			return quic.DialAddr(ctx, fmt.Sprintf("127.0.0.1:%d", port), cfg, qc)
		},
	}
	defer tr.Close()
	var lastErr error
	for i := 0; i < 20; i++ { // le serveur démarre dans une goroutine
		req, _ := http.NewRequest(http.MethodGet, "https://"+host+"/", nil)
		ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		resp, err := tr.RoundTrip(req.WithContext(ctx))
		if err == nil {
			b, _ := io.ReadAll(resp.Body)
			resp.Body.Close()
			cancel()
			return resp, string(b)
		}
		cancel()
		lastErr = err
		time.Sleep(150 * time.Millisecond)
	}
	t.Fatalf("aucune réponse HTTP/3 sur le port UDP %d : %v", port, lastErr)
	return nil, ""
}

// La configuration générée au premier démarrage (images Docker) ne contient pas quic_port : le serveur écoutait alors sur
// un port UDP éphémère, injoignable sur 443/udp. Sans port QUIC, HTTP/3 suit le port HTTPS.
func TestStartDefaultsQUICPortToHTTPSPort(t *testing.T) {
	port := freeUDPPort(t)
	cfg := &config.EdgeConfig{}
	cfg.Network.BindAddress = "127.0.0.1"
	cfg.Network.HTTPSPort = port // QUICPort reste à 0

	cert, key := selfSigned(t, "x.test")
	store := edgetls.NewCertStore()
	if err := store.StorePEM("x.test", cert, key); err != nil {
		t.Fatal(err)
	}
	q := &QUICServer{}
	if err := q.Start(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, _ = w.Write([]byte("ok")) }), store); err != nil {
		t.Fatal(err)
	}
	defer q.Stop()

	if q.Port() != port {
		t.Fatalf("Port() = %d, attendu le port HTTPS %d", q.Port(), port)
	}
	resp, body := get(t, port, "x.test")
	if resp.StatusCode != http.StatusOK || body != "ok" || resp.Proto != "HTTP/3.0" {
		t.Fatalf("réponse = %s %d %q", resp.Proto, resp.StatusCode, body)
	}
	if want := fmt.Sprintf(`h3=":%d"; ma=86400`, port); resp.Header.Get("Alt-Svc") != want {
		t.Errorf("Alt-Svc = %q, attendu %q", resp.Header.Get("Alt-Svc"), want)
	}
}

func TestStartKeepsExplicitQUICPort(t *testing.T) {
	https, quicPort := freeUDPPort(t), freeUDPPort(t)
	cfg := &config.EdgeConfig{}
	cfg.Network.BindAddress = "127.0.0.1"
	cfg.Network.HTTPSPort, cfg.Network.QUICPort = https, quicPort

	cert, key := selfSigned(t, "x.test")
	store := edgetls.NewCertStore()
	_ = store.StorePEM("x.test", cert, key)
	q := &QUICServer{}
	if err := q.Start(cfg, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}), store); err != nil {
		t.Fatal(err)
	}
	defer q.Stop()
	if q.Port() != quicPort {
		t.Fatalf("Port() = %d, attendu le port QUIC explicite %d", q.Port(), quicPort)
	}
	if resp, _ := get(t, quicPort, "x.test"); resp.Header.Get("Alt-Svc") != fmt.Sprintf(`h3=":%d"; ma=86400`, quicPort) {
		t.Errorf("Alt-Svc = %q", resp.Header.Get("Alt-Svc"))
	}
}
