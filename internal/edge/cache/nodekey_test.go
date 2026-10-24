// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package cache_test

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/cache"
	"github.com/vincamok/goproxify/internal/edge/router"
)

// isolate retire toute clé de l'environnement et envoie la clé générée dans un dossier de test.
func isolate(t *testing.T) string {
	t.Helper()
	for _, k := range []string{cache.NodeKeyEnv, cache.NodeKeyFileEnv, cache.PreviousSecretsEnv,
		"GPX_CONTROL_PLANE_AUTH_TOKEN", "GPX_CONTROLPLANE_AUTH_TOKEN", "GPX_PAIRING_SECRET"} {
		t.Setenv(k, "")
	}
	path := filepath.Join(t.TempDir(), "node.key")
	t.Setenv(cache.NodeKeyPathEnv, path)
	return path
}

func snapshotWith(id string) *cache.Snapshot {
	return &cache.Snapshot{SavedAt: time.Now(), Routes: []*router.Route{{ID: id, Host: id + ".example.fr"}}}
}

func TestEnsureNodeKeyGeneratesOnceAndKeepsIt(t *testing.T) {
	path := isolate(t)
	created, err := cache.EnsureNodeKey()
	if err != nil || !created {
		t.Fatalf("première fois : créée=%v err=%v", created, err)
	}
	first, _ := os.ReadFile(path)
	if len(first) < 64 {
		t.Fatalf("clé trop courte : %d", len(first))
	}
	if runtime.GOOS != "windows" {
		if info, _ := os.Stat(path); info.Mode().Perm() != 0o600 {
			t.Fatalf("droits = %v, attendu 0600", info.Mode().Perm())
		}
	}
	created, err = cache.EnsureNodeKey()
	if err != nil || created {
		t.Fatalf("seconde fois : créée=%v err=%v", created, err)
	}
	if again, _ := os.ReadFile(path); string(again) != string(first) {
		t.Fatal("la clé existante ne change pas")
	}
}

// Un fichier de clé illisible ou trop court n'est jamais écrasé.
func TestEnsureNodeKeyNeverOverwritesAnInvalidFile(t *testing.T) {
	path := isolate(t)
	if err := os.WriteFile(path, []byte("court"), 0o600); err != nil {
		t.Fatal(err)
	}
	created, err := cache.EnsureNodeKey()
	if err == nil || created {
		t.Fatalf("un fichier invalide doit être signalé : créée=%v err=%v", created, err)
	}
	if got, _ := os.ReadFile(path); string(got) != "court" {
		t.Fatal("le fichier invalide n'est pas écrasé")
	}
}

// Une clé fournie par l'environnement ou un fichier de secret empêche toute génération.
func TestEnsureNodeKeyIsSkippedWhenProvided(t *testing.T) {
	path := isolate(t)
	t.Setenv(cache.NodeKeyEnv, "cle-fournie-par-l-environnement-0123456789")
	if created, err := cache.EnsureNodeKey(); created || err != nil {
		t.Fatalf("créée=%v err=%v", created, err)
	}
	if _, err := os.Stat(path); err == nil {
		t.Fatal("aucun fichier ne doit être créé")
	}
}

func TestResolveSecretOrder(t *testing.T) {
	path := isolate(t)
	t.Setenv("GPX_PAIRING_SECRET", "pair-xyz")
	if got := cache.ResolveSecret(""); got != "pair-xyz" {
		t.Fatalf("sans clé locale : %q", got)
	}
	if _, err := cache.EnsureNodeKey(); err != nil {
		t.Fatal(err)
	}
	generated, _ := os.ReadFile(path)
	if got := cache.ResolveSecret(""); got == "pair-xyz" || got == "" || got+"\n" != string(generated) {
		t.Fatalf("la clé générée passe avant le secret d'appairage : %q", got)
	}
	keyFile := filepath.Join(t.TempDir(), "secret")
	if err := os.WriteFile(keyFile, []byte("depuis-un-fichier-de-secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cache.NodeKeyFileEnv, keyFile)
	if got := cache.ResolveSecret(""); got != "depuis-un-fichier-de-secret" {
		t.Fatalf("fichier de secret : %q", got)
	}
	t.Setenv(cache.NodeKeyEnv, "depuis-l-environnement")
	if got := cache.ResolveSecret(""); got != "depuis-l-environnement" {
		t.Fatalf("variable : %q", got)
	}
}

// Des copies écrites avec le secret d'appairage sont relues après le passage à la clé locale, réécrites avec elle, et
// ne dépendent alors plus du secret d'appairage.
func TestMigrationFromThePairingSecretThenRotation(t *testing.T) {
	isolate(t)
	t.Setenv("GPX_PAIRING_SECRET", "ancien-secret-d-appairage")
	file := filepath.Join(t.TempDir(), "edge-cache.gpx")

	old := cache.New(file, cache.ResolveSecret(""))
	if err := old.Save(snapshotWith("avant")); err != nil {
		t.Fatal(err)
	}

	if _, err := cache.EnsureNodeKey(); err != nil {
		t.Fatal(err)
	}
	neu := cache.New(file, cache.ResolveSecret(""))
	snap, err := neu.Load()
	if err != nil || snap == nil || snap.Routes[0].ID != "avant" {
		t.Fatalf("relecture avec l'ancien secret d'appairage : %v %+v", err, snap)
	}

	// Le secret d'appairage change : les copies, réécrites avec la clé locale, restent lisibles.
	t.Setenv("GPX_PAIRING_SECRET", "nouveau-secret-d-appairage")
	after := cache.New(file, cache.ResolveSecret(""))
	snap, err = after.Load()
	if err != nil || snap == nil || snap.Routes[0].ID != "avant" {
		t.Fatalf("après la rotation du secret d'appairage : %v %+v", err, snap)
	}
}

// Fournir plus tard une clé hors du disque ne rend pas illisible ce que la clé générée avait chiffré.
func TestSwitchingToAProvidedKeyKeepsTheGeneratedKeyReadable(t *testing.T) {
	isolate(t)
	file := filepath.Join(t.TempDir(), "edge-cache.gpx")
	if _, err := cache.EnsureNodeKey(); err != nil {
		t.Fatal(err)
	}
	if err := cache.New(file, cache.ResolveSecret("")).Save(snapshotWith("genere")); err != nil {
		t.Fatal(err)
	}
	t.Setenv(cache.NodeKeyEnv, "cle-hors-du-disque-0123456789abcdef0123")
	snap, err := cache.New(file, cache.ResolveSecret("")).Load()
	if err != nil || snap == nil || snap.Routes[0].ID != "genere" {
		t.Fatalf("la clé générée reste lisible : %v %+v", err, snap)
	}
}

// Les fichiers chiffrés à part (SaveFile/LoadFile) suivent la même règle, et l'ancien secret d'une autre passerelle reste inutile.
func TestLoadFileFollowsTheMigration(t *testing.T) {
	isolate(t)
	t.Setenv("GPX_PAIRING_SECRET", "ancien-secret-d-appairage")
	file := filepath.Join(t.TempDir(), "log-ip-key.gpx")
	type payload struct{ N int }
	if err := cache.New("", cache.ResolveSecret("")).SaveFile(file, payload{N: 7}); err != nil {
		t.Fatal(err)
	}
	if _, err := cache.EnsureNodeKey(); err != nil {
		t.Fatal(err)
	}
	var got payload
	ok, err := cache.New("", cache.ResolveSecret("")).LoadFile(file, &got)
	if err != nil || !ok || got.N != 7 {
		t.Fatalf("relecture avec la clé locale : ok=%v err=%v %+v", ok, err, got)
	}
	t.Setenv("GPX_PAIRING_SECRET", "autre")
	ok, err = cache.New("", cache.ResolveSecret("")).LoadFile(file, &got)
	if err != nil || !ok || got.N != 7 {
		t.Fatalf("après la rotation du secret d'appairage : ok=%v err=%v", ok, err)
	}
	other := cache.New("", "secret-sans-rapport")
	if _, err := other.LoadFile(file, &got); err == nil {
		t.Fatal("un secret sans rapport ne déchiffre pas")
	}
}
