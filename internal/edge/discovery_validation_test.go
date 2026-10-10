// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"bytes"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"github.com/vincamok/goproxify/internal/modules"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func announce(s *Server, body string) *httptest.ResponseRecorder {
	rr := httptest.NewRecorder()
	s.handleAgentContainerStart(rr, httptest.NewRequest(http.MethodPost, "/internal/v1/agent/containers", bytes.NewBufferString(body)))
	return rr
}

func containerBody(extra string) string {
	b := `{"id":"docker:abc:app.example.fr","host":"app.example.fr","backends":["http://10.0.0.1:80"],"agent_name":"a","container_id":"abc123def456"`
	if extra != "" {
		b += "," + extra
	}
	return b + "}"
}

// Les routes issues des labels passent par les mêmes contrôles de sécurité que le dry-run d'un proxy :
// une route mal protégée n'est pas enregistrée, plutôt que servie sans filtre.
func TestDiscovery_RejectsInvalidLabelSecurity(t *testing.T) {
	for name, extra := range map[string]string{
		"mode du filtre IP":   `"ip_filter":{"mode":"blok","cidrs":["10.0.0.0/8"]}`,
		"CIDR invalide":       `"ip_filter":{"mode":"deny","cidrs":["10.0.0.0/40"]}`,
		"étiquette en texte":  `"ip_filter":"deny:pas-une-adresse"`,
		"filtre vide":         `"ip_filter":"deny:"`,
		"pays invalide":       `"geo_ip":{"mode":"deny","countries":["CHINE"]}`,
		"geo illisible":       `"geo_ip":"???"`,
		"regex WAF":           `"waf":{"enabled":true,"custom_rules":[{"pattern":"("}]}`,
		"fournisseur de défi": `"bot":{"enabled":true,"challenge_provider":"recaptcha"}`,
	} {
		s := testEdgeServer()
		rr := announce(s, containerBody(extra))
		if rr.Code != http.StatusUnprocessableEntity {
			t.Errorf("%s : %d (attendu 422) %s", name, rr.Code, rr.Body.String())
			continue
		}
		if _, ok := s.table.ByHost("app.example.fr"); ok {
			t.Errorf("%s : route enregistrée malgré le refus", name)
		}
	}
}

func TestDiscovery_AcceptsValidLabelSecurity(t *testing.T) {
	for name, extra := range map[string]string{
		"sans sécurité":   ``,
		"filtre IP":       `"ip_filter":{"mode":"allow","cidrs":["10.0.0.0/8","203.0.113.7"]}`,
		"filtre en texte": `"ip_filter":"allow:10.0.0.0/8,192.168.0.0/16"`,
		"geo":             `"geo_ip":{"mode":"deny","countries":["cn","RU"]}`,
		"bot":             `"bot":{"enabled":true,"mode":"challenge"}`,
		"waf":             `"waf":{"enabled":true,"mode":"detect"}`,
		"snippet absent":  `"snippet_ids":["pas-encore-pousse"]`,
	} {
		s := testEdgeServer()
		if rr := announce(s, containerBody(extra)); rr.Code != http.StatusNoContent {
			t.Errorf("%s : %d %s", name, rr.Code, rr.Body.String())
		}
	}
}

// Une nouvelle annonce invalide ne modifie pas la route déjà enregistrée.
func TestDiscovery_InvalidUpdateLeavesRouteUnchanged(t *testing.T) {
	s := testEdgeServer()
	if rr := announce(s, containerBody(`"ip_filter":{"mode":"allow","cidrs":["10.0.0.0/8"]}`)); rr.Code != http.StatusNoContent {
		t.Fatalf("première annonce : %d", rr.Code)
	}
	if rr := announce(s, containerBody(`"ip_filter":{"mode":"blok","cidrs":["0.0.0.0/0"]}`)); rr.Code != http.StatusUnprocessableEntity {
		t.Fatalf("annonce invalide : %d", rr.Code)
	}
	rt, ok := s.table.ByHost("app.example.fr")
	if !ok || rt.IPFilter == nil || rt.IPFilter.Mode != "allow" || !strings.Contains(strings.Join(rt.IPFilter.CIDRs, ","), "10.0.0.0/8") {
		t.Fatalf("route modifiée : %+v", rt)
	}
}

// Les labels que l'agent n'a pas su lire (jwt sans JWKS, mtls sans CA…) font refuser la route.
func TestDiscovery_AgentLabelErrorsRejectTheRoute(t *testing.T) {
	s := testEdgeServer()
	rr := announce(s, containerBody(`"label_errors":["goproxify.jwt=pas-une-url : valeur illisible"]`))
	if rr.Code != http.StatusUnprocessableEntity || !strings.Contains(rr.Body.String(), "goproxify.jwt") {
		t.Fatalf("label illisible : %d %s", rr.Code, rr.Body.String())
	}
	if _, ok := s.table.ByHost("app.example.fr"); ok {
		t.Error("route enregistrée malgré une protection demandée et illisible")
	}
}

func TestDiscovery_PluginLabels(t *testing.T) {
	s := pluginTestServer(t, t.TempDir())
	installBody(t, s, "geo", `{}`, []string{"request"}, func(m *plugins.Manifest) {
		m.Fields = []modules.Field{{Key: "header", Label: "En-tête", Kind: modules.KindText, Required: true}}
	})
	// Plugin installé et configuration conforme : la route porte le plugin.
	rr := announce(s, containerBody(`"plugins":[{"name":"geo","config":{"header":"X-Geo"}}]`))
	if rr.Code != http.StatusNoContent {
		t.Fatalf("config valide : %d %s", rr.Code, rr.Body.String())
	}
	rt, _ := s.table.ByHost("app.example.fr")
	if rt == nil || len(rt.Plugins) != 1 || rt.Plugins[0].Name != "geo" || rt.Plugins[0].Config["header"] != "X-Geo" {
		t.Fatalf("plugins de la route = %+v", rt)
	}
	// Configuration qui ne respecte pas le manifeste : refusée.
	s2 := pluginTestServer(t, t.TempDir())
	installBody(t, s2, "geo", `{}`, []string{"request"}, func(m *plugins.Manifest) {
		m.Fields = []modules.Field{{Key: "header", Label: "En-tête", Kind: modules.KindText, Required: true}}
	})
	if rr := announce(s2, containerBody(`"plugins":[{"name":"geo"}]`)); rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("champ requis manquant : %d", rr.Code)
	}
	// Plugin pas encore poussé par l'Admin : toléré (la route refuse le trafic en 503 d'ici là).
	s3 := pluginTestServer(t, t.TempDir())
	if rr := announce(s3, containerBody(`"plugins":[{"name":"arrive-plus-tard"}]`)); rr.Code != http.StatusNoContent {
		t.Errorf("plugin pas encore installé : %d %s", rr.Code, rr.Body.String())
	}
	// Plugin sans hook HTTP sur une route HTTP : refusé.
	s4 := pluginTestServer(t, t.TempDir())
	installBody(t, s4, "l4", `{}`, []string{"connect"}, nil)
	if rr := announce(s4, containerBody(`"plugins":[{"name":"l4"}]`)); rr.Code != http.StatusUnprocessableEntity {
		t.Errorf("hook inapplicable : %d", rr.Code)
	}
}
