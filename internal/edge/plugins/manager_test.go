// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	edgecache "github.com/vincamok/goproxify/internal/edge/cache"
)

func pkgFor(name string, wasm []byte, mutate ...func(*Manifest)) Package {
	m := manifest()
	m.Name = name
	for _, f := range mutate {
		f(&m)
	}
	sum := sha256.Sum256(wasm)
	return Package{Manifest: m, SHA256: hex.EncodeToString(sum[:]), Wasm: wasm}
}

func newManager(t *testing.T, dir string) *Manager {
	t.Helper()
	m := NewManager(edgecache.New(filepath.Join(dir, "cache.gpx"), "cle-passerelle"), filepath.Join(dir, "plugins"), nil)
	t.Cleanup(func() { m.Close(context.Background()) })
	return m
}

// Un plugin installé est stocké chiffré, rechargé après un redémarrage sans Admin, et son module n'est
// lisible en clair dans aucun fichier.
func TestManager_InstallEncryptedAndSurvivesRestart(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	wasm := staticPlugin(`{"action":"deny","status":403,"body":"stockage"}`)
	m := newManager(t, dir)
	if err := m.Install(ctx, pkgFor("denier", wasm)); err != nil {
		t.Fatal(err)
	}
	err := filepath.WalkDir(dir, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		if b, _ := os.ReadFile(p); bytes.Contains(b, wasm[:16]) || bytes.Contains(b, []byte("stockage")) {
			t.Errorf("module en clair dans %s", p)
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}

	restarted := newManager(t, dir)
	n, errs := restarted.LoadAll(ctx)
	if n != 1 || len(errs) != 0 {
		t.Fatalf("rechargés = %d, erreurs = %v", n, errs)
	}
	p, ok := restarted.Get("denier")
	if !ok {
		t.Fatal("plugin absent après redémarrage")
	}
	out, err := p.Call(ctx, HookRequest, RequestInput{})
	if err != nil || out.Action != ActionDeny || out.Body != "stockage" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	if list := restarted.List(); len(list) != 1 || list[0].Manifest.Name != "denier" {
		t.Fatalf("liste = %+v", list)
	}
}

func TestManager_InstallRefusals(t *testing.T) {
	ctx := context.Background()
	m := newManager(t, t.TempDir())
	wasm := staticPlugin(`{}`)
	noSHA := pkgFor("a", wasm)
	noSHA.SHA256 = ""
	wrongSHA := pkgFor("b", wasm)
	wrongSHA.SHA256 = "00"
	badManifest := pkgFor("Bad Name", wasm)
	for name, pkg := range map[string]Package{"sans empreinte": noSHA, "empreinte fausse": wrongSHA, "manifeste": badManifest, "module": pkgFor("c", []byte("x"))} {
		if err := m.Install(ctx, pkg); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	if len(m.List()) != 0 {
		t.Errorf("plugins chargés malgré les refus : %+v", m.List())
	}
}

func TestManager_ReplaceAndRemove(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	m := newManager(t, dir)
	if err := m.Install(ctx, pkgFor("p", staticPlugin(`{"action":"deny","body":"v1"}`))); err != nil {
		t.Fatal(err)
	}
	if err := m.Install(ctx, pkgFor("p", staticPlugin(`{"action":"deny","body":"v2"}`))); err != nil {
		t.Fatal(err)
	}
	p, _ := m.Get("p")
	if out, _ := p.Call(ctx, HookRequest, RequestInput{}); out.Body != "v2" {
		t.Errorf("version active = %q", out.Body)
	}
	if err := m.Remove(ctx, "p"); err != nil {
		t.Fatal(err)
	}
	if _, ok := m.Get("p"); ok {
		t.Error("plugin toujours chargé")
	}
	if n, _ := newManager(t, dir).LoadAll(ctx); n != 0 {
		t.Errorf("plugin rechargé après suppression : %d", n)
	}
	if err := m.Remove(ctx, "../etc"); err == nil {
		t.Error("nom de chemin accepté")
	}
}

// Un paquet corrompu n'empêche pas les autres de se charger.
func TestManager_LoadAllSkipsBadPackages(t *testing.T) {
	ctx := context.Background()
	dir := t.TempDir()
	m := newManager(t, dir)
	if err := m.Install(ctx, pkgFor("bon", staticPlugin(`{}`))); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "plugins", "corrompu.gpx"), []byte("pas chiffré"), 0o600); err != nil {
		t.Fatal(err)
	}
	r := newManager(t, dir)
	n, errs := r.LoadAll(ctx)
	if n != 1 || len(errs) != 1 {
		t.Fatalf("rechargés = %d, erreurs = %v", n, errs)
	}
	if _, ok := r.Get("bon"); !ok {
		t.Error("plugin sain non chargé")
	}
}

// La politique d'erreur : un plugin en échec refuse (503) par défaut, laisse passer sur demande.
func TestEvaluate_OnErrorPolicy(t *testing.T) {
	ctx := context.Background()
	deny := load(t, manifest(), trapPlugin())
	out, err := deny.Evaluate(ctx, HookRequest, RequestInput{})
	if err == nil || out.Action != ActionDeny || out.Status != 503 {
		t.Errorf("on_error deny : %+v %v", out, err)
	}
	m := manifest()
	m.OnError = OnErrorAllow
	allow := load(t, m, trapPlugin())
	out, err = allow.Evaluate(ctx, HookRequest, RequestInput{})
	if err == nil || out.Action != ActionAllow {
		t.Errorf("on_error allow : %+v %v", out, err)
	}
	ok := load(t, manifest(), staticPlugin(`{"action":"deny","status":402}`))
	if out, err := ok.Evaluate(ctx, HookRequest, RequestInput{}); err != nil || out.Status != 402 {
		t.Errorf("plugin sain : %+v %v", out, err)
	}
}
