// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func TestImportedCertCountsAsExpiringOnItsDay(t *testing.T) {
	h := setupMCPDB(t)
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	// Expire dans 30 j moins 1 min : le même jour UTC que datetime('now', '+30 days') (sauf à minuit),
	// qu'une date RFC3339 dépassait toute la journée ('T' > ' ').
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "mcp.example.com"},
		DNSNames:     []string{"mcp.example.com"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(30*24*time.Hour - time.Minute),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &priv.PublicKey, priv)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, _ := x509.MarshalECPrivateKey(priv)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	if _, err := h.toolImportCert(r, map[string]any{
		"cert_pem": string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})),
		"key_pem":  string(pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER})),
	}); err != nil {
		t.Fatal(err)
	}
	ov, err := h.toolGetSecurityOverview(r)
	if err != nil {
		t.Fatal(err)
	}
	if n := ov.(map[string]any)["expiring_certs"]; n != 1 {
		t.Errorf("get_security_overview : %v certificat expirant sous 30 j, attendu 1", n)
	}
}

func TestSilenceToolsStoreDatesComparableToCurrentTimestamp(t *testing.T) {
	h := setupMCPDB(t)
	r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
	ny := time.FixedZone("", -5*3600)
	if _, err := h.toolCreateSilence(r, map[string]any{
		"name":      "maintenance",
		"starts_at": time.Now().Add(-time.Minute).In(ny).Format(time.RFC3339),
		"ends_at":   time.Now().Add(time.Hour).In(ny).Format(time.RFC3339),
	}); err != nil {
		t.Fatal(err)
	}
	starts := time.Now().Add(-time.Minute).UTC()
	if _, err := h.toolImportAutomation(r, map[string]any{"yaml": "silences:\n  - name: import\n    starts_at: " +
		starts.Format(time.RFC3339) + "\n    ends_at: " + starts.Add(time.Hour).Format(time.RFC3339) + "\n"}); err != nil {
		t.Fatal(err)
	}
	// Prédicat du moteur d'alertes (isSilenced).
	var n int
	h.DB.QueryRow(`SELECT COUNT(*) FROM automation_silences WHERE starts_at <= CURRENT_TIMESTAMP AND ends_at >= CURRENT_TIMESTAMP`).Scan(&n) //nolint:errcheck
	if n != 2 {
		t.Errorf("%d silence actif, attendu 2 (create_silence en UTC-5 et import RFC3339)", n)
	}
	list, err := h.toolListSilences(r)
	if err != nil {
		t.Fatal(err)
	}
	for _, s := range list.([]map[string]any) {
		if s["active"] != true {
			t.Errorf("list_silences : %v doit être actif", s)
		}
	}
}
