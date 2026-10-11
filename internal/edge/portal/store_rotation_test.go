// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"path/filepath"
	"testing"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
)

// La base du portail (coffres d'identifiants) dérive sa clé du secret d'appairage quand GPX_PORTAL_MASTER_KEY n'est pas
// posée : une rotation du secret ne doit ni la rendre illisible ni la laisser sous l'ancienne clé.
func TestStoreRotation_PreviousSecretReadsThenReencrypts(t *testing.T) {
	path := filepath.Join(t.TempDir(), "portal.gpx")
	t.Setenv(edgecache.PreviousSecretsEnv, "")
	old := NewStore(path, "ancien-secret")
	old.snap.Catalog = []CatalogTarget{{ID: "t1", Name: "base de production"}}
	if err := old.Save(); err != nil {
		t.Fatal(err)
	}

	if err := NewStore(path, "nouveau-secret").Load(); err == nil {
		t.Fatal("la base se relit avec un autre secret sans que l'ancien soit déclaré")
	}

	t.Setenv(edgecache.PreviousSecretsEnv, "ancien-secret")
	fresh := NewStore(path, "nouveau-secret")
	if err := fresh.Load(); err != nil {
		t.Fatalf("relecture avec l'ancien secret : %v", err)
	}
	if len(fresh.snap.Catalog) != 1 || fresh.snap.Catalog[0].Name != "base de production" {
		t.Fatalf("catalogue relu : %+v", fresh.snap.Catalog)
	}

	t.Setenv(edgecache.PreviousSecretsEnv, "")
	after := NewStore(path, "nouveau-secret")
	if err := after.Load(); err != nil || len(after.snap.Catalog) != 1 {
		t.Fatalf("après retrait de l'ancien secret : %v", err)
	}
	if err := NewStore(path, "ancien-secret").Load(); err == nil {
		t.Error("la base reste lisible avec l'ancien secret après migration")
	}
}
