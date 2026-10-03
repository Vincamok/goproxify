// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"errors"
	"math/big"
	"net"
	"testing"
	"time"
)

func selfSigned(t *testing.T, names ...string) tls.Certificate {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	tpl := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: names[0]}, DNSNames: names,
		NotBefore: time.Now().Add(-time.Hour), NotAfter: time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		t.Fatal(err)
	}
	return tls.Certificate{Certificate: [][]byte{der}, PrivateKey: key}
}

// handshake joue un handshake TLS complet en mémoire ; retourne l'état client, le SNI vu par le
// serveur et les erreurs.
func handshake(t *testing.T, srvCfg, cliCfg *tls.Config) (cli tls.ConnectionState, seenSNI string, cliErr error) {
	t.Helper()
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer ln.Close()
	srvCfg = srvCfg.Clone()
	srvCfg.GetCertificate = func(h *tls.ClientHelloInfo) (*tls.Certificate, error) {
		seenSNI = h.ServerName
		c := selfSigned(t, "a.example.com", "ech.example.com")
		return &c, nil
	}
	done := make(chan struct{})
	go func() {
		defer close(done)
		conn, err := ln.Accept()
		if err != nil {
			return
		}
		defer conn.Close()
		conn.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
		tls.Server(conn, srvCfg).Handshake()               //nolint:errcheck
	}()
	raw, err := net.Dial("tcp", ln.Addr().String())
	if err != nil {
		t.Fatal(err)
	}
	raw.SetDeadline(time.Now().Add(10 * time.Second)) //nolint:errcheck
	c := tls.Client(raw, cliCfg)
	cliErr = c.Handshake()
	raw.Close()
	<-done
	return c.ConnectionState(), seenSNI, cliErr
}

func newKeySet(t *testing.T, publicName string, id uint8) (ECHKey, []byte) {
	t.Helper()
	cfg, priv, err := GenerateECHKey(publicName, id)
	if err != nil {
		t.Fatal(err)
	}
	return ECHKey{Config: cfg, PrivateKey: priv, SendAsRetry: true}, ECHConfigList(cfg)
}

func TestECH_Accepted(t *testing.T) {
	key, list := newKeySet(t, "ech.example.com", 7)
	m := NewECHManager()
	m.Bind(&tls.Config{MinVersion: tls.VersionTLS12})
	if err := m.Set([]ECHKey{key}); err != nil {
		t.Fatal(err)
	}
	st, sni, err := handshake(t, m.Config(), &tls.Config{
		ServerName: "a.example.com", EncryptedClientHelloConfigList: list,
		InsecureSkipVerify: true, //nolint:gosec // cert de test auto-signé
	})
	if err != nil {
		t.Fatal(err)
	}
	if !st.ECHAccepted {
		t.Fatal("ECH non accepté")
	}
	if sni != "a.example.com" {
		t.Fatalf("SNI vu par le serveur = %q (attendu le nom interne)", sni)
	}
}

func TestECH_RotationKeepsRetiredKeyDecrypting(t *testing.T) {
	oldKey, oldList := newKeySet(t, "ech.example.com", 1)
	newKey, newList := newKeySet(t, "ech.example.com", 2)
	oldKey.SendAsRetry = false
	m := NewECHManager()
	m.Bind(&tls.Config{})
	if err := m.Set([]ECHKey{newKey, oldKey}); err != nil {
		t.Fatal(err)
	}
	for name, list := range map[string][]byte{"ancienne": oldList, "nouvelle": newList} {
		st, _, err := handshake(t, m.Config(), &tls.Config{
			ServerName: "a.example.com", EncryptedClientHelloConfigList: list, InsecureSkipVerify: true, //nolint:gosec
		})
		if err != nil || !st.ECHAccepted {
			t.Fatalf("config %s : accepted=%v err=%v", name, st.ECHAccepted, err)
		}
	}
}

// Un client doté d'une config inconnue est rejeté et reçoit la config courante pour réessayer.
func TestECH_UnknownConfigGetsRetryList(t *testing.T) {
	key, list := newKeySet(t, "ech.example.com", 3)
	_, staleList := newKeySet(t, "ech.example.com", 9)
	m := NewECHManager()
	m.Bind(&tls.Config{})
	m.Set([]ECHKey{key}) //nolint:errcheck

	_, _, err := handshake(t, m.Config(), &tls.Config{
		ServerName: "a.example.com", EncryptedClientHelloConfigList: staleList,
		EncryptedClientHelloRejectionVerify: func(tls.ConnectionState) error { return nil },
	})
	var rej *tls.ECHRejectionError
	if !errors.As(err, &rej) {
		t.Fatalf("err = %v, attendu ECHRejectionError", err)
	}
	if !bytes.Equal(rej.RetryConfigList, list) {
		t.Fatal("liste de réessai différente de la config courante")
	}
}

func TestECH_DisabledWithoutKeys(t *testing.T) {
	m := NewECHManager()
	base := &tls.Config{}
	m.Bind(base)
	if m.Config() != base {
		t.Fatal("sans clé, la config de base doit être servie telle quelle")
	}
	if len(m.Keys()) != 0 {
		t.Fatal("clés inattendues")
	}
	if err := m.Set([]ECHKey{{Config: []byte("x")}}); err == nil {
		t.Fatal("clé invalide acceptée")
	}
}

func TestValidateECHPublicName(t *testing.T) {
	for name, ok := range map[string]bool{
		"ech.example.com": true, "a.b.example.fr": true,
		"": false, "*.example.com": false, "example": false, "10.0.0.1": false, "a b.com": false, ".a.com": false, "a.com.": false,
	} {
		if (ValidateECHPublicName(name) == nil) != ok {
			t.Errorf("ValidateECHPublicName(%q) ok=%v attendu", name, ok)
		}
	}
}
