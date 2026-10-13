// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/acme"
	"github.com/vincamok/goproxify/internal/modules"
)

func TestToolListDNSProvidersMasksSecrets(t *testing.T) {
	store := acme.NewProviderStore(filepath.Join(t.TempDir(), "acme-providers.yaml"))
	if _, err := store.Create("prod", "cloudflare", map[string]string{"api_token": "cf-very-secret", "zone_id": "z1"}); err != nil {
		t.Fatal(err)
	}
	res, err := (&Handler{DNSProviders: store}).toolListDNSProviders()
	if err != nil {
		t.Fatal(err)
	}
	list := res.([]acme.ProviderEntry)
	if len(list) != 1 || list[0].Params["api_token"] != modules.Masque || list[0].Params["zone_id"] != "z1" {
		t.Fatalf("secret non masqué ou paramètre perdu : %+v", list)
	}
	if _, err := (&Handler{}).toolListDNSProviders(); err == nil {
		t.Fatal("erreur attendue sans magasin de fournisseurs")
	}
}

func TestDNSProviderTypesFilter(t *testing.T) {
	if all := dnsProviderTypes(""); len(all) < 33 {
		t.Fatalf("%d types, au moins 33 attendus", len(all))
	}
	got := dnsProviderTypes("OCEAN")
	if len(got) != 1 || got[0].Type != "digitalocean" {
		t.Fatalf("filtre « OCEAN » : %+v", got)
	}
	if got := dnsProviderTypes("inexistant"); got == nil || len(got) != 0 {
		t.Fatalf("liste vide (non nulle) attendue : %#v", got)
	}
}
