// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcpaccess

import (
	"net/http/httptest"
	"testing"

	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
)

// L'allowlist par défaut ne laisse passer que les réseaux privés : un appelant d'Internet ne la franchit pas en
// écrivant X-Forwarded-For: 10.0.0.1.
func TestMatchAllowlistIgnoresForgedForwardedFor(t *testing.T) {
	t.Cleanup(func() { edgelog.SetTrustedProxies(nil) })
	edgelog.SetTrustedProxies(nil)
	allow := []string{"10.0.0.0/8", "192.168.0.0/16", "203.0.113.5"}

	from := func(remote, xff string) bool {
		r := httptest.NewRequest("POST", "/mcp", nil)
		r.RemoteAddr = remote
		if xff != "" {
			r.Header.Set("X-Forwarded-For", xff)
		}
		return matchAllowlist(allow, r)
	}

	if from("198.51.100.9:4000", "10.0.0.1") {
		t.Error("un pair public ne doit pas se faire passer pour 10.0.0.1")
	}
	if from("198.51.100.9:4000", "") {
		t.Error("un pair public hors liste est refusé")
	}
	if !from("203.0.113.5:4000", "") {
		t.Error("un pair listé est accepté")
	}
	if !from("10.1.1.1:4000", "") {
		t.Error("un pair privé listé est accepté")
	}
	// derrière la passerelle (pair privé de confiance) : l'adresse transmise fait foi
	if !from("10.1.1.1:4000", "6.6.6.6, 203.0.113.5") {
		t.Error("derrière un proxy de confiance, l'adresse transmise listée est acceptée")
	}
	if from("10.1.1.1:4000", "198.51.100.9") {
		t.Error("derrière un proxy de confiance, une adresse transmise hors liste est refusée")
	}
}
