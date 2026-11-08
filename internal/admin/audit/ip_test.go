// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"net/http/httptest"
	"testing"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
)

// L'adresse écrite au journal d'audit ne vient d'un en-tête que si la connexion arrive d'un proxy de confiance : sinon
// n'importe qui, authentifié ou non, y inscrit l'adresse de son choix.
func TestIPFromIgnoresForwardedHeaderFromUntrustedPeer(t *testing.T) {
	t.Cleanup(func() { edgelog.SetTrustedProxies(nil) })
	edgelog.SetTrustedProxies(nil)

	r := httptest.NewRequest("POST", "/api/v1/auth/login", nil)
	r.RemoteAddr = "203.0.113.50:5555"
	r.Header.Set("X-Forwarded-For", "10.0.0.1")
	if got := IPFrom(r); got != "203.0.113.50" {
		t.Fatalf("IPFrom = %q, attendu l'adresse du pair", got)
	}

	r.RemoteAddr = "10.0.0.9:5555" // passerelle devant l'Admin
	r.Header.Set("X-Forwarded-For", "6.6.6.6, 198.51.100.4")
	if got := IPFrom(r); got != "198.51.100.4" {
		t.Fatalf("derrière un proxy de confiance, IPFrom = %q, attendu 198.51.100.4", got)
	}

	edgelog.SetTrustedProxies([]string{"none"})
	if got := IPFrom(r); got != "10.0.0.9" {
		t.Fatalf("avec none, IPFrom = %q, attendu l'adresse du pair", got)
	}
}
