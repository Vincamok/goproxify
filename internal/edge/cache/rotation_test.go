// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package cache

import (
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

type payload struct {
	Valeur string `json:"valeur"`
}

// Changer le secret d'appairage change la clé du cache : sans l'ancien secret, la passerelle ne relit plus ses copies
// locales et repart de zéro (son autonomie tient à ces fichiers).
func TestRotation_WithoutPreviousSecretLocalDataIsLost(t *testing.T) {
	dir := t.TempDir()
	snapPath, filePath := filepath.Join(dir, "edge-cache.gpx"), filepath.Join(dir, "config.gpx")
	t.Setenv(PreviousSecretsEnv, "")

	old := New(snapPath, "ancien-secret")
	if err := old.Save(&Snapshot{Routes: []*router.Route{{ID: "r1", Host: "a.example.fr"}}}); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveFile(filePath, payload{Valeur: "x"}); err != nil {
		t.Fatal(err)
	}

	fresh := New(snapPath, "nouveau-secret")
	if _, err := fresh.Load(); err == nil {
		t.Error("le snapshot se relit avec un autre secret sans que l'ancien soit déclaré")
	}
	var p payload
	if _, err := fresh.LoadFile(filePath, &p); err == nil {
		t.Error("le fichier se relit avec un autre secret sans que l'ancien soit déclaré")
	}
}

func TestRotation_PreviousSecretReadsThenReencrypts(t *testing.T) {
	dir := t.TempDir()
	snapPath, filePath := filepath.Join(dir, "edge-cache.gpx"), filepath.Join(dir, "config.gpx")
	t.Setenv(PreviousSecretsEnv, "")
	old := New(snapPath, "ancien-secret")
	if err := old.Save(&Snapshot{Routes: []*router.Route{{ID: "r1", Host: "a.example.fr"}}}); err != nil {
		t.Fatal(err)
	}
	if err := old.SaveFile(filePath, payload{Valeur: "conservé"}); err != nil {
		t.Fatal(err)
	}

	t.Setenv(PreviousSecretsEnv, "un-autre, ancien-secret ,")
	fresh := New(snapPath, "nouveau-secret")
	snap, err := fresh.Load()
	if err != nil || snap == nil || len(snap.Routes) != 1 || snap.Routes[0].Host != "a.example.fr" {
		t.Fatalf("snapshot relu avec l'ancien secret : %+v %v", snap, err)
	}
	var p payload
	if ok, err := fresh.LoadFile(filePath, &p); err != nil || !ok || p.Valeur != "conservé" {
		t.Fatalf("fichier relu avec l'ancien secret : %+v ok=%v err=%v", p, ok, err)
	}

	// Réécrits avec le secret courant : la variable peut être retirée, plus rien ne dépend de l'ancien secret.
	t.Setenv(PreviousSecretsEnv, "")
	after := New(snapPath, "nouveau-secret")
	if snap, err := after.Load(); err != nil || snap == nil || len(snap.Routes) != 1 {
		t.Errorf("snapshot après retrait de l'ancien secret : %v", err)
	}
	var q payload
	if ok, err := after.LoadFile(filePath, &q); err != nil || !ok || q.Valeur != "conservé" {
		t.Errorf("fichier après retrait de l'ancien secret : %+v %v", q, err)
	}
	// Et l'ancien secret ne relit plus rien : une fois migrée, la donnée n'est plus lisible avec lui.
	if _, err := New(snapPath, "ancien-secret").Load(); err == nil {
		t.Error("le snapshot reste lisible avec l'ancien secret après migration")
	}
}
