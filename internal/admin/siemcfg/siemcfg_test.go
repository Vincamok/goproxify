// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siemcfg

import (
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/edge/siem"
)

func TestMaskKeepsSecretsOutAndMergeRestoresThem(t *testing.T) {
	stored := siem.Config{Enabled: true, Destinations: []siem.Destination{
		{ID: "d1", Name: "Splunk", Type: siem.TypeHTTP, Address: "https://splunk.example/in", Headers: map[string]string{"Authorization": "Bearer s3cret"}},
	}}
	masked := Mask(stored)
	if masked.Destinations[0].Headers["Authorization"] != Masked {
		t.Fatalf("en-tête non masqué : %v", masked.Destinations[0].Headers)
	}
	if stored.Destinations[0].Headers["Authorization"] != "Bearer s3cret" {
		t.Fatal("Mask a modifié la configuration source")
	}

	// L'interface renvoie la config masquée, modifiée ailleurs : le secret enregistré est retrouvé.
	masked.Destinations[0].Name = "Splunk prod"
	masked.Destinations = append(masked.Destinations, siem.Destination{Name: "Nouveau", Type: siem.TypeHTTP, Address: "https://x.example/",
		Headers: map[string]string{"X-Key": "neuf"}})
	got := Merge(stored, masked)
	if got.Destinations[0].Headers["Authorization"] != "Bearer s3cret" || got.Destinations[0].Name != "Splunk prod" {
		t.Errorf("secret non restauré : %+v", got.Destinations[0])
	}
	if got.Destinations[1].ID == "" || got.Destinations[1].Headers["X-Key"] != "neuf" {
		t.Errorf("nouvelle destination : %+v", got.Destinations[1])
	}
	if err := got.Validate(); err != nil {
		t.Errorf("configuration fusionnée invalide : %v", err)
	}
	// Une valeur réellement modifiée remplace le secret.
	masked.Destinations[0].Headers["Authorization"] = "Bearer autre"
	if got := Merge(stored, masked); got.Destinations[0].Headers["Authorization"] != "Bearer autre" {
		t.Error("un nouvel en-tête doit remplacer l'ancien")
	}
}

func TestSaveAndLoadRoundTrip(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if cfg := Load(db); cfg.Enabled || len(cfg.Destinations) != 0 {
		t.Fatalf("configuration par défaut : %+v", cfg)
	}
	want := siem.Config{Enabled: true, Destinations: []siem.Destination{{ID: "a", Name: "S", Type: siem.TypeSyslog, Address: "siem:6514", TLS: true, Kinds: []string{"access"}}}}
	if err := Save(db, want); err != nil {
		t.Fatal(err)
	}
	got := Load(db)
	if !got.Enabled || len(got.Destinations) != 1 || got.Destinations[0].Address != "siem:6514" || !got.Destinations[0].TLS || got.Destinations[0].Kinds[0] != "access" {
		t.Fatalf("relu : %+v", got)
	}
}

func TestForNodeKeepsOnlyTheDestinationsAimedAtTheGateway(t *testing.T) {
	cfg := siem.Config{Enabled: true, Destinations: []siem.Destination{
		{ID: "all", Name: "Tous", Type: siem.TypeHTTP, Address: "http://a/"},
		{ID: "paris", Name: "Paris", Type: siem.TypeHTTP, Address: "http://b/", Nodes: []string{"gw-paris"}},
		{ID: "duo", Name: "Duo", Type: siem.TypeOTLP, Address: "http://c/v1/logs", Nodes: []string{"gw-lyon", "gw-paris"}},
	}}
	ids := func(c siem.Config) (out []string) {
		for _, d := range c.Destinations {
			if d.Nodes != nil {
				t.Errorf("%s : le champ nodes est transmis à la passerelle", d.ID)
			}
			out = append(out, d.ID)
		}
		return out
	}
	if got := ids(ForNode(cfg, "gw-paris")); len(got) != 3 {
		t.Errorf("gw-paris : %v", got)
	}
	if got := ids(ForNode(cfg, "gw-lyon")); len(got) != 2 || got[0] != "all" || got[1] != "duo" {
		t.Errorf("gw-lyon : %v", got)
	}
	if got := ids(ForNode(cfg, "gw-nice")); len(got) != 1 || got[0] != "all" {
		t.Errorf("gw-nice : %v", got)
	}
	if cfg.Destinations[1].Nodes == nil {
		t.Error("ForNode a modifié la configuration source")
	}
	if out := ForNode(siem.Config{Enabled: false}, "gw-paris"); out.Enabled {
		t.Error("l'état activé n'est pas repris")
	}
	// Une destination qui visait la passerelle puis ne la vise plus disparaît de sa configuration : elle y est éteinte.
	cfg.Destinations[1].Nodes = []string{"gw-lyon"}
	if got := ids(ForNode(cfg, "gw-paris")); len(got) != 2 {
		t.Errorf("après retrait de gw-paris : %v", got)
	}
}
