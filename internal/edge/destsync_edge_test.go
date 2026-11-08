// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/destsync"
)

func TestPortalPushPayloadCarriesDestSources(t *testing.T) {
	var p portalPushPayload
	raw := `{"enabled":true,"dest_sources":[{"id":"s1","type":"proxmox","enabled":true,"interval_s":120,"config":{"url":"https://pve:8006","token_secret":"x"}}]}`
	if err := json.Unmarshal([]byte(raw), &p); err != nil {
		t.Fatal(err)
	}
	if len(p.DestSources) != 1 || p.DestSources[0].ID != "s1" || p.DestSources[0].Config["token_secret"] != "x" {
		t.Fatalf("sources : %+v", p.DestSources)
	}
	// Admin plus ancien : le champ est absent, les sources en place ne doivent pas être touchées.
	var old portalPushPayload
	_ = json.Unmarshal([]byte(`{"enabled":true}`), &old)
	if old.DestSources != nil {
		t.Fatal("absent doit rester nil (distinct de la liste vide)")
	}
	// Persisté puis relu (copie locale chiffrée) : les secrets survivent à un redémarrage.
	again, _ := json.Marshal(p)
	var back portalPushPayload
	if err := json.Unmarshal(again, &back); err != nil || back.DestSources[0].Config["token_secret"] != "x" {
		t.Fatalf("aller-retour : %v %+v", err, back.DestSources)
	}
}

func TestApplyDestSourcesRunsOnlyOnTheMemberThatHostsThePortal(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	s := &Server{destSync: destsync.NewRunner(func(destsync.Inventory) {})}
	s.destSync.Start(ctx)
	src := []destsync.SourceConfig{{ID: "s1", Type: "proxmox", Enabled: true, Config: map[string]any{}}}

	s.applyDestSources(portalPushPayload{Enabled: true, DestSources: src})
	if got := s.destSync.Active(); len(got) != 1 {
		t.Fatalf("portail actif : la source tourne (%v)", got)
	}
	s.applyDestSources(portalPushPayload{Enabled: true, DestSources: nil})
	if got := s.destSync.Active(); len(got) != 1 {
		t.Fatalf("Admin ancien (champ absent) : rien ne change (%v)", got)
	}
	s.applyDestSources(portalPushPayload{Enabled: true, HAStandby: true, DestSources: src})
	if got := s.destSync.Active(); len(got) != 0 {
		t.Fatalf("réplica en attente : aucune interrogation du fournisseur (%v)", got)
	}
	s.applyDestSources(portalPushPayload{Enabled: true, DestSources: src})
	s.applyDestSources(portalPushPayload{Enabled: false, DestSources: src})
	if got := s.destSync.Active(); len(got) != 0 {
		t.Fatalf("portail éteint : aucune source (%v)", got)
	}
	s.applyDestSources(portalPushPayload{Enabled: true, DestSources: src})
	s.applyDestSources(portalPushPayload{Enabled: true, DestSources: []destsync.SourceConfig{}})
	if got := s.destSync.Active(); len(got) != 0 {
		t.Fatalf("liste vide : toutes les sources sont retirées (%v)", got)
	}
}

func TestHandleDestSourceTestReadsTheProviderFromTheGateway(t *testing.T) {
	provider := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api2/json/cluster/resources" {
			_, _ = w.Write([]byte(`{"data":[{"id":"lxc/9","type":"lxc","vmid":9,"name":"ct","node":"n1","status":"running"}]}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer provider.Close()

	call := func(body string) destSourceTestResponse {
		rr := httptest.NewRecorder()
		(&Server{}).handleDestSourceTest(rr, httptest.NewRequest(http.MethodPost, "/", strings.NewReader(body)))
		var out destSourceTestResponse
		if err := json.Unmarshal(rr.Body.Bytes(), &out); err != nil {
			t.Fatalf("réponse : %v %s", err, rr.Body.String())
		}
		return out
	}
	ok := call(`{"type":"proxmox","config":{"url":"` + provider.URL + `","token_id":"a@pve!t","token_secret":"s"}}`)
	if !ok.OK || ok.Count != 1 || ok.Machines[0].ExternalID != "lxc/9" {
		t.Fatalf("essai réussi : %+v", ok)
	}
	if bad := call(`{"type":"proxmox","config":{"url":"` + provider.URL + `"}}`); bad.OK || !strings.Contains(bad.Error, "token_id") {
		t.Fatalf("configuration incomplète : %+v", bad)
	}
	if bad := call(`{"type":"inconnu","config":{}}`); bad.OK || bad.Error == "" {
		t.Fatalf("type inconnu : %+v", bad)
	}
}
