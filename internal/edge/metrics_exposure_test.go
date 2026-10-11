// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"net/http/httptest"
	"testing"
)

// /metrics sur le port public livrait à n'importe quel client les hôtes, les URL de backends et les compteurs de
// sécurité, et masquait le /metrics des applications : il n'est servi qu'à la demande.
func TestPublicMux_MetricsOnlyWhenOptedIn(t *testing.T) {
	s := &Server{}
	req := httptest.NewRequest("GET", "/metrics", nil)
	if _, pattern := s.newMux(false).Handler(req); pattern != "/" {
		t.Errorf("par défaut /metrics doit suivre le routage normal (motif %q)", pattern)
	}
	if _, pattern := s.newMux(true).Handler(req); pattern != "/metrics" {
		t.Errorf("avec GPX_METRICS_PUBLIC /metrics est servi (motif %q)", pattern)
	}
}

func TestMetricsPublicEnv(t *testing.T) {
	for v, want := range map[string]bool{"": false, "0": false, "no": false, "1": true, "true": true, "YES": true, " yes ": true} {
		t.Setenv("GPX_METRICS_PUBLIC", v)
		if got := metricsPublic(); got != want {
			t.Errorf("GPX_METRICS_PUBLIC=%q → %v, attendu %v", v, got, want)
		}
	}
}
