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

func TestOperatePermissionCoversReadsAndWritesAndClosesTheRest(t *testing.T) {
	cases := []struct {
		method, path, want string
	}{
		{"GET", "/api/v1/alert-events", "alerts:read"},
		{"POST", "/api/v1/alert-events/12/ack", "alerts:ack"},
		{"DELETE", "/api/v1/alert-events/12", "unmapped"},
		{"GET", "/api/v1/alert-rules", "alerts:read"},
		{"POST", "/api/v1/alert-rules", "alerts:rules"},
		{"PUT", "/api/v1/alert-rules/r1", "alerts:rules"},
		{"POST", "/api/v1/alert-rules/simulate", "alerts:rules"},
		{"GET", "/api/v1/alert-channels", "alert_channels:read"},
		{"POST", "/api/v1/alert-channels", "alert_channels:manage"},
		{"POST", "/api/v1/alert-channels/c1/test", "alert_channels:test"},
		{"GET", "/api/v1/certs", "certs:read"},
		{"GET", "/api/v1/certs/app.corp.io/pem", "certs:read"},
		{"POST", "/api/v1/certs", "certs:manage"},
		{"POST", "/api/v1/certs/import", "certs:manage"},
		{"DELETE", "/api/v1/certs/app.corp.io", "certs:manage"},
		// Déploiement et jetons de récupération : leurs cases du catalogue.
		{"POST", "/api/v1/certs/app.corp.io/deploy-targets", "certs:deploy"},
		{"GET", "/api/v1/certs/app.corp.io/deploy-targets", "certs:deploy"},
		{"POST", "/api/v1/certs/app.corp.io/pull-tokens", "certs:export_key"},
		{"GET", "/api/v1/certs/app.corp.io/pull-tokens", "certs:export_key"},
		{"PUT", "/api/v1/certs/app.corp.io/inconnu", "unmapped"},
		{"GET", "/api/v1/domains", "domains:read"},
		{"POST", "/api/v1/domains", "domains:manage"},
		{"POST", "/api/v1/domains/d1/renew", "domains:manage"},
		{"PATCH", "/api/v1/inconnu", "unmapped"},
	}
	for _, c := range cases {
		got, gated := operatePermission(httptest.NewRequest(c.method, c.path, nil))
		if got != c.want || !gated {
			t.Errorf("%s %s : (%q, %v), attendu %q", c.method, c.path, got, gated, c.want)
		}
	}
	if got, _ := readPermission(httptest.NewRequest("GET", "/api/v1/audit", nil)); got != "audit:read" {
		t.Errorf("audit : %q", got)
	}
}

func TestPortalSecurityAndAutomationPermissions(t *testing.T) {
	type tc struct {
		method, path, want string
	}
	check := func(name string, resolve func(*http.Request) (string, bool), cases []tc) {
		for _, c := range cases {
			got, gated := resolve(httptest.NewRequest(c.method, c.path, nil))
			if got != c.want || !gated {
				t.Errorf("%s %s %s : (%q, %v), attendu %q", name, c.method, c.path, got, gated, c.want)
			}
		}
	}
	check("portail", portalPermission, []tc{
		{"GET", "/api/v1/portal", "portal_templates:read"},
		{"PUT", "/api/v1/portal", "portal_templates:manage"},
		{"POST", "/api/v1/portal/push", "portal_templates:manage"},
		{"GET", "/api/v1/portal-page-templates", "portal_templates:read"},
		{"GET", "/api/v1/portal/users", "portal_users:read"},
		{"DELETE", "/api/v1/portal/groups/g1", "portal_users:manage"},
		{"GET", "/api/v1/portal/destinations", "portal_catalog:read"},
		{"POST", "/api/v1/portal/destination-groups", "portal_catalog:manage"},
		{"GET", "/api/v1/portal/policy", "portal_policies:read"},
		{"PUT", "/api/v1/portal/policy", "portal_policies:manage"},
		{"GET", "/api/v1/portal/audit", "portal_audit:read"},
		{"POST", "/api/v1/portal/audit", "unmapped"},
		{"GET", "/api/v1/portal/access-requests", "portal_requests:read"},
		{"POST", "/api/v1/portal/access-requests/r1/approve", "portal_requests:decide"},
		{"GET", "/api/v1/portal/recordings", "portal_recordings:list"},
		{"GET", "/api/v1/portal/recordings/r1", "portal_recordings:replay"},
		{"DELETE", "/api/v1/portal/recordings/r1", "portal_recordings:delete"},
		{"GET", "/api/v1/portal/sessions", "portal_sessions:read"},
		{"GET", "/api/v1/portal/sessions/s1/watch", "portal_sessions:observe"},
		{"POST", "/api/v1/portal/sessions/s1/terminate", "portal_sessions:cut"},
		{"GET", "/api/v1/portal/inconnu", "unmapped"},
	})
	check("sécurité", securityPermission, []tc{
		{"GET", "/api/v1/security", "netsec:read"},
		{"GET", "/api/v1/security/overview", "netsec:read"},
		{"GET", "/api/v1/security/bans", "netsec:read"},
		{"GET", "/api/v1/security/bans/whitelist", "netsec:read"},
		{"POST", "/api/v1/security/bans", "netsec:respond"},
		{"DELETE", "/api/v1/security/bans/b1", "netsec:respond"},
		{"POST", "/api/v1/security/bans/whitelist", "netsec:respond"},
		{"POST", "/api/v1/security/bans/import", "bans:import"},
		{"GET", "/api/v1/security/ip-trace", "netsec:analyse"},
		{"GET", "/api/v1/security/attack-ref/dossiers", "attack_ref:read"},
		{"POST", "/api/v1/security/attack-ref/run", "attack_ref:write"},
		{"POST", "/api/v1/security/vulnscan", "netsec:analyse"},
		{"PUT", "/api/v1/security/vulnscan/config", "unmapped"},
		{"PATCH", "/api/v1/security/cves/c1", "netsec:respond"},
		{"POST", "/api/v1/security/asn/ban", "netsec:respond"},
		// Flotte, CrowdSec, objectifs : administrateurs seulement ; les moteurs et la surface suivent leurs permissions.
		{"GET", "/api/v1/security/waf-config", "engines:read"},
		{"PUT", "/api/v1/security/waf-config", "engines:tune"},
		{"GET", "/api/v1/security/threat-config", "engines:read"},
		{"GET", "/api/v1/security/threat-config/suggestions", "engines:read"},
		{"POST", "/api/v1/security/threat-config/simulate", "engines:simulate"},
		{"POST", "/api/v1/security/threat-config/calibrate", "engines:simulate"},
		{"GET", "/api/v1/security/threat-references", "engines:read"},
		{"POST", "/api/v1/security/threat-config/inconnu", "unmapped"},
		{"PUT", "/api/v1/security/threat-config", "engines:tune"},
		{"PUT", "/api/v1/security/fleet", "unmapped"},
		{"GET", "/api/v1/security/surface/report", "surface:read"},
		{"GET", "/api/v1/security/surface", "surface:read"},
		{"POST", "/api/v1/security/surface/reset", "surface:learn"},
		{"POST", "/api/v1/security/surface/accept", "surface:learn"},
		{"POST", "/api/v1/security/surface/relax", "surface:learn"},
		{"POST", "/api/v1/security/surface/enforce", "surface:enforce"},
		{"GET", "/api/v1/security/crowdsec", "unmapped"},
	})
	check("automatisation", automationPermission, []tc{
		{"GET", "/api/v1/automation/flows", "automation:read"},
		{"GET", "/api/v1/automation/runs", "automation:read"},
		{"GET", "/api/v1/automation/catalog", "automation:read"},
		{"POST", "/api/v1/automation/flows", "automation:edit"},
		{"PUT", "/api/v1/automation/flows/f1", "automation:edit"},
		{"POST", "/api/v1/automation/flows/f1/run", "automation:run"},
		{"POST", "/api/v1/automation/flows/f1/detach", "automation:edit"},
		{"POST", "/api/v1/automation/runs/r1/approve", "automation:approve"},
		{"POST", "/api/v1/automation/runs/r1/reject", "automation:approve"},
		{"POST", "/api/v1/automation/runs/r1/cancel", "automation:run"},
		{"POST", "/api/v1/automation/runs/r1/replay", "automation:run"},
		{"POST", "/api/v1/automation/simulate", "automation:edit"},
		{"POST", "/api/v1/automation/silences", "automation:edit"},
		{"POST", "/api/v1/automation/import", "automation:edit"},
		{"GET", "/api/v1/automation/inconnu", "unmapped"},
		{"DELETE", "/api/v1/automation/runs/r1", "unmapped"},
	})
}

func TestSharedObjectReadsNeedTheirPermission(t *testing.T) {
	for path, want := range map[string]string{
		"/api/v1/snippets": "snippets:read", "/api/v1/snippets/s1": "snippets:read", "/api/v1/detector-types": "snippets:read",
		"/api/v1/ip-profiles": "ip_profiles:read", "/api/v1/ip-profiles/p1": "ip_profiles:read",
	} {
		if got, gated := readPermission(httptest.NewRequest("GET", path, nil)); got != want || !gated {
			t.Errorf("%s : (%q, %v), attendu %q", path, got, gated, want)
		}
	}
}
