// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

// Un client n'apprend l'existence de HTTP/3 que par l'en-tête Alt-Svc d'une réponse reçue en HTTPS : sans lui personne n'essaie QUIC.
func TestAltSvcAdvertisedOverTLS(t *testing.T) {
	s, _ := redirectGateway(t,
		&router.Route{ID: "std", Host: "std.test", TLSEnabled: true},
		&router.Route{ID: "mtls", Host: "mtls.test", TLSEnabled: true, MTLS: &router.MTLSConfig{Enabled: true, CACertPEM: "x", RequireClientCert: true}},
	)
	want := `h3=":443"; ma=86400`

	s.quicPort.Store(443)
	if got := call(s, http.MethodGet, "https://std.test/", "198.51.100.9", true, nil).Header().Get("Alt-Svc"); got != want {
		t.Errorf("réponse HTTPS : Alt-Svc = %q, attendu %q", got, want)
	}
	if got := call(s, http.MethodGet, "http://std.test/", "198.51.100.9", false, nil).Header().Get("Alt-Svc"); got != "" {
		t.Errorf("réponse en clair : Alt-Svc = %q (un client l'ignorerait, ne pas l'envoyer)", got)
	}
	if got := call(s, http.MethodGet, "https://mtls.test/", "198.51.100.9", true, nil).Header().Get("Alt-Svc"); got != "" {
		t.Errorf("route mTLS : Alt-Svc = %q (QUIC ne porte pas de certificat client)", got)
	}

	s.quicPort.Store(8443)
	if got := call(s, http.MethodGet, "https://std.test/", "198.51.100.9", true, nil).Header().Get("Alt-Svc"); got != `h3=":8443"; ma=86400` {
		t.Errorf("port QUIC non standard : Alt-Svc = %q", got)
	}

	s.quicPort.Store(0) // QUIC non démarré : rien à annoncer
	if got := call(s, http.MethodGet, "https://std.test/", "198.51.100.9", true, nil).Header().Get("Alt-Svc"); got != "" {
		t.Errorf("QUIC arrêté : Alt-Svc = %q", got)
	}
}
