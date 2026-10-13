// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"crypto/ed25519"
	"encoding/base64"
	"os"
	"path/filepath"
	"strings"
	"testing"

	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

func pubB64(p ed25519.PublicKey) string { return base64.StdEncoding.EncodeToString(p) }

func signedPkg(t *testing.T, name string, wasm []byte, priv ed25519.PrivateKey) Package {
	t.Helper()
	pkg := pkgFor(name, wasm)
	m := pkg.Manifest
	if err := m.Normalize(); err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(priv, m, pkg.SHA256)
	if err != nil {
		t.Fatal(err)
	}
	pkg.Signature = sig
	return pkg
}

// Sans clé épinglée, rien ne change : l'empreinte seule est contrôlée.
func TestTrust_NotPinnedKeepsTheHistoricalBehaviour(t *testing.T) {
	m := newManager(t, t.TempDir())
	if m.Pinned() {
		t.Fatal("aucune variable définie : pas d'épinglage")
	}
	if err := m.Install(context.Background(), pkgFor("libre", pt.Static(`{"action":"allow"}`))); err != nil {
		t.Fatalf("un paquet non signé doit passer sans épinglage : %v", err)
	}
	if info := m.List(); len(info) != 1 || info[0].Verified {
		t.Errorf("liste : %+v", info)
	}
}

func TestTrust_PinnedKeysRefuseWhatTheyDidNotSign(t *testing.T) {
	pub, priv, _ := GenerateKey()
	_, otherPriv, _ := GenerateKey()
	t.Setenv(TrustedKeysEnv, pubB64(pub))
	ctx := context.Background()
	wasm := pt.Static(`{"action":"allow"}`)
	m := newManager(t, t.TempDir())
	if !m.Pinned() {
		t.Fatal("épinglage attendu")
	}

	if err := m.Install(ctx, pkgFor("sans-signature", wasm)); err == nil || !strings.Contains(err.Error(), "signature absente") {
		t.Errorf("non signé : %v", err)
	}
	if err := m.Install(ctx, signedPkg(t, "autre-cle", wasm, otherPriv)); err == nil || !strings.Contains(err.Error(), "non épinglée") {
		t.Errorf("clé inconnue : %v", err)
	}
	// Une signature valable d'un autre paquet ne couvre pas celui-ci.
	stolen := signedPkg(t, "vole", wasm, priv)
	stolen.Manifest.Name = "autre-nom"
	if err := m.Install(ctx, stolen); err == nil {
		t.Error("une signature ne doit pas valoir pour un autre manifeste")
	}
	// Module changé après signature (l'empreinte annoncée est celle du module signé).
	tampered := signedPkg(t, "altere", wasm, priv)
	tampered.Wasm = pt.Static(`{"action":"deny","status":403,"body":"x"}`)
	if err := m.Install(ctx, tampered); err == nil {
		t.Error("un module altéré doit être refusé")
	}
	if len(m.List()) != 0 {
		t.Fatalf("rien ne doit être installé : %+v", m.List())
	}

	if err := m.Install(ctx, signedPkg(t, "signe", wasm, priv)); err != nil {
		t.Fatalf("paquet signé par la clé épinglée : %v", err)
	}
	if info := m.List(); len(info) != 1 || !info[0].Verified {
		t.Errorf("liste : %+v", info)
	}
}

// La version qui tourne reste en place quand une mise à jour est refusée (Sync).
func TestTrust_RefusedUpdateKeepsTheRunningVersion(t *testing.T) {
	pub, priv, _ := GenerateKey()
	t.Setenv(TrustedKeysEnv, pubB64(pub))
	ctx := context.Background()
	m := newManager(t, t.TempDir())
	v1 := signedPkg(t, "p", pt.Static(`{"action":"allow"}`), priv)
	if _, _, errs := m.Sync(ctx, []Package{v1}); len(errs) != 0 {
		t.Fatalf("v1 : %v", errs)
	}
	v2 := pkgFor("p", pt.Static(`{"action":"deny","status":403,"body":"v2"}`)) // non signé
	if _, _, errs := m.Sync(ctx, []Package{v2}); len(errs) != 1 {
		t.Fatalf("v2 non signée : %v", errs)
	}
	p, ok := m.Get("p")
	if !ok || p.SHA256 != v1.SHA256 {
		t.Error("la version signée doit rester active")
	}
}

// Les copies chiffrées déjà stockées sont revérifiées au redémarrage : un paquet installé avant l'épinglage, ou
// signé par une clé retirée depuis, n'est plus chargé.
func TestTrust_StoredPackagesAreRecheckedAtStartup(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	pub, priv, _ := GenerateKey()
	wasm := pt.Static(`{"action":"allow"}`)

	// Installé avant l'épinglage (non signé) et un autre signé.
	open := newManager(t, dir)
	if err := open.Install(ctx, pkgFor("ancien", wasm)); err != nil {
		t.Fatal(err)
	}
	t.Setenv(TrustedKeysEnv, pubB64(pub))
	pinned := newManager(t, dir)
	if err := pinned.Install(ctx, signedPkg(t, "recent", wasm, priv)); err != nil {
		t.Fatal(err)
	}

	restarted := newManager(t, dir)
	n, errs := restarted.LoadAll(ctx)
	if n != 1 || len(errs) != 1 || !strings.Contains(errs[0].Error(), "ancien") {
		t.Fatalf("rechargement : %d chargé(s), erreurs %v", n, errs)
	}
	if _, ok := restarted.Get("recent"); !ok {
		t.Error("le paquet signé doit être rechargé sans l'Admin")
	}
	if _, ok := restarted.Get("ancien"); ok {
		t.Error("le paquet non signé ne doit plus être chargé")
	}

	// Clé retirée : le paquet signé n'est plus accepté non plus.
	other, _, _ := GenerateKey()
	t.Setenv(TrustedKeysEnv, pubB64(other))
	rotated := newManager(t, dir)
	if n, _ := rotated.LoadAll(ctx); n != 0 {
		t.Errorf("clé retirée : %d plugin(s) chargé(s)", n)
	}
}

// Une configuration d'épinglage cassée refuse tout, elle ne désactive pas la vérification.
func TestTrust_BrokenConfigurationFailsClosed(t *testing.T) {
	_, priv, _ := GenerateKey()
	t.Setenv(TrustedKeysEnv, "ceci n'est pas une clé")
	m := newManager(t, t.TempDir())
	if !m.Pinned() {
		t.Fatal("l'épinglage doit rester actif")
	}
	if err := m.Install(context.Background(), signedPkg(t, "x", pt.Static(`{"action":"allow"}`), priv)); err == nil {
		t.Fatal("aucune clé valide : tout doit être refusé")
	}
}

func TestTrust_KeysFileAndList(t *testing.T) {
	pubA, privA, _ := GenerateKey()
	pubB, privB, _ := GenerateKey()
	file := filepath.Join(t.TempDir(), "keys")
	if err := os.WriteFile(file, []byte("# clés du dépôt\n"+pubB64(pubA)+"  # éditeur A\n\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv(TrustedKeysFileEnv, file)
	t.Setenv(TrustedKeysEnv, pubB64(pubB))
	m := newManager(t, t.TempDir())
	wasm := pt.Static(`{"action":"allow"}`)
	for name, priv := range map[string]ed25519.PrivateKey{"a": privA, "b": privB} {
		if err := m.Install(context.Background(), signedPkg(t, name, wasm, priv)); err != nil {
			t.Errorf("clé %s : %v", name, err)
		}
	}
}
