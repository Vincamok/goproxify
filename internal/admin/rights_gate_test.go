// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestReadPermissionMapsEachReadToACataloguePermission(t *testing.T) {
	cases := []struct {
		method, path string
		want         string
		gated        bool
	}{
		{"GET", "/api/v1/logs", "logs:read", true},
		{"GET", "/api/v1/logs/facets", "logs:read", true},
		{"GET", "/api/v1/logs/live", "logs:read", true},
		{"GET", "/api/v1/logs/export", "logs:export", true},
		{"GET", "/api/v1/logs/settings", "logs_settings:read", true},
		{"GET", "/api/v1/logs/une-route-oubliee", "unmapped", true},
		{"GET", "/api/v1/certs", "certs:read", true},
		{"GET", "/api/v1/certs/acme-monitor", "certs:read", true},
		{"GET", "/api/v1/certs/app.corp.io/pem", "certs:read", true},
		{"GET", "/api/v1/certs/app.corp.io/deploy-targets", "certs:deploy", true},
		{"GET", "/api/v1/certs/app.corp.io/pull-tokens", "certs:deploy", true},
		{"GET", "/api/v1/cert-deploy-types", "certs:read", true},
		{"GET", "/api/v1/alert-events", "alerts:read", true},
		{"GET", "/api/v1/alert-rules/triggers", "alerts:read", true},
		{"GET", "/api/v1/alert-channels", "alert_channels:read", true},
		{"GET", "/api/v1/alert-channel-types", "alert_channels:read", true},
		{"GET", "/api/v1/metrics/proxies", "dashboard:read", true},
		{"GET", "/api/v1/prism/kpis", "dashboard:read", true},
		// Les écritures sont réservées aux administrateurs par l'enveloppe qui suit.
		{"POST", "/api/v1/logs/settings", "", false},
		{"DELETE", "/api/v1/certs/app.corp.io", "", false},
		{"PUT", "/api/v1/prism/slo", "", false},
	}
	for _, c := range cases {
		got, gated := readPermission(httptest.NewRequest(c.method, c.path, nil))
		if got != c.want || gated != c.gated {
			t.Errorf("%s %s : (%q, %v), attendu (%q, %v)", c.method, c.path, got, gated, c.want, c.gated)
		}
	}
	_ = http.MethodGet
}
