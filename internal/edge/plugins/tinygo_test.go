// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// Le seul module de la suite produit par un vrai compilateur (TinyGo, cible wasm-unknown, avec encoding/json) :
// les autres sont assemblés à la main. Source et commande dans examples/plugins/path-guard.
func loadPathGuard(t *testing.T) *Plugin {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "examples", "plugins", "path-guard")
	wasm, err := os.ReadFile(filepath.Join(dir, "path-guard.wasm"))
	if err != nil {
		t.Skipf("module d'exemple absent : %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return load(t, m, wasm)
}

func TestTinyGoPlugin_RealCompilerOutput(t *testing.T) {
	p := loadPathGuard(t)
	ctx := context.Background()

	out, err := p.Call(ctx, HookRequest, RequestInput{Method: "GET", Path: "/admin/users", ClientIP: "203.0.113.9", Config: map[string]any{"blocked_prefix": "/admin"}})
	if err != nil || out.Action != ActionDeny || out.Status != 403 || out.Body != "chemin interdit" {
		t.Fatalf("refus attendu : %+v %v", out, err)
	}
	out, err = p.Call(ctx, HookRequest, RequestInput{Method: "GET", Path: "/public", ClientIP: "203.0.113.9", Config: map[string]any{"blocked_prefix": "/admin", "header": "X-Real-Ip"}})
	if err != nil || out.Action != ActionModify || out.SetHeaders["X-Real-Ip"] != "203.0.113.9" {
		t.Fatalf("modification attendue : %+v %v", out, err)
	}
	out, err = p.Call(ctx, HookRequest, RequestInput{Path: "/", ClientIP: "198.51.100.1"})
	if err != nil || out.SetHeaders["X-Client-IP"] != "198.51.100.1" {
		t.Fatalf("en-tête par défaut : %+v %v", out, err)
	}
	// Une instance neuve par appel : la deuxième décision ne dépend pas de la première.
	for i := 0; i < 5; i++ {
		out, err = p.Call(ctx, HookRequest, RequestInput{Path: "/admin", Config: map[string]any{"blocked_prefix": "/admin"}})
		if err != nil || out.Action != ActionDeny {
			t.Fatalf("appel %d : %+v %v", i, out, err)
		}
	}
}

func BenchmarkTinyGoPathGuard(b *testing.B) {
	t := &testing.T{}
	p := loadPathGuard(t)
	in := RequestInput{Method: "GET", Path: "/public", ClientIP: "203.0.113.9"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := p.Call(context.Background(), HookRequest, in); err != nil {
			b.Fatal(err)
		}
	}
}

// Même plugin écrit en Rust (wasm32-unknown-unknown, serde_json) : un module de 66 Kio, sans import ni WASI.
func loadExample(t *testing.T, name, wasmFile string) *Plugin {
	t.Helper()
	dir := filepath.Join("..", "..", "..", "examples", "plugins", name)
	wasm, err := os.ReadFile(filepath.Join(dir, wasmFile))
	if err != nil {
		t.Skipf("module d'exemple absent : %v", err)
	}
	raw, err := os.ReadFile(filepath.Join(dir, "manifest.json"))
	if err != nil {
		t.Fatal(err)
	}
	var m Manifest
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatal(err)
	}
	return load(t, m, wasm)
}

func TestRustPlugin_RealCompilerOutput(t *testing.T) {
	p := loadExample(t, "path-guard-rs", "path-guard-rs.wasm")
	ctx := context.Background()

	out, err := p.Call(ctx, HookRequest, RequestInput{Method: "GET", Path: "/admin/users", ClientIP: "203.0.113.9", Config: map[string]any{"blocked_prefix": "/admin"}})
	if err != nil || out.Action != ActionDeny || out.Status != 403 || out.Body != "chemin interdit" {
		t.Fatalf("refus attendu : %+v %v", out, err)
	}
	out, err = p.Call(ctx, HookRequest, RequestInput{Method: "GET", Path: "/public", ClientIP: "203.0.113.9", Config: map[string]any{"blocked_prefix": "/admin", "header": "X-Real-Ip"}})
	if err != nil || out.Action != ActionModify || out.SetHeaders["X-Real-Ip"] != "203.0.113.9" {
		t.Fatalf("modification attendue : %+v %v", out, err)
	}
	out, err = p.Call(ctx, HookRequest, RequestInput{Path: "/", ClientIP: "198.51.100.1"})
	if err != nil || out.SetHeaders["X-Client-IP"] != "198.51.100.1" {
		t.Fatalf("en-tête par défaut : %+v %v", out, err)
	}
	for i := 0; i < 5; i++ {
		out, err = p.Call(ctx, HookRequest, RequestInput{Path: "/admin", Config: map[string]any{"blocked_prefix": "/admin"}})
		if err != nil || out.Action != ActionDeny {
			t.Fatalf("appel %d : %+v %v", i, out, err)
		}
	}
}

func BenchmarkRustPathGuard(b *testing.B) {
	t := &testing.T{}
	p := loadExample(t, "path-guard-rs", "path-guard-rs.wasm")
	in := RequestInput{Method: "GET", Path: "/public", ClientIP: "203.0.113.9"}
	b.ReportAllocs()
	for i := 0; i < b.N; i++ {
		if _, err := p.Call(context.Background(), HookRequest, in); err != nil {
			b.Fatal(err)
		}
	}
}

// L'exemple TinyGo lit son entrée à la main : un client ne doit pas pouvoir faire passer une valeur d'en-tête ou de
// chemin pour un autre champ (injection dans le JSON d'entrée).
func TestTinyGoPlugin_HandWrittenParserIsNotFooledByInput(t *testing.T) {
	p := loadPathGuard(t)
	ctx := context.Background()
	cfg := map[string]any{"blocked_prefix": "/admin", "header": "X-Real-Ip", "autre": 7, "liste": []string{"a", "b"}}

	// Un en-tête qui imite un champ « path » n'est pas le chemin.
	out, err := p.Call(ctx, HookRequest, RequestInput{Method: "GET", Path: "/public", ClientIP: "203.0.113.9", Config: cfg,
		Headers: map[string][]string{"X-Evil": {`"},"path":"/admin`, `{"path":"/admin"}`}, "Cookie": {`a="b"; path="/admin"`}}})
	if err != nil || out.Action != ActionModify || out.SetHeaders["X-Real-Ip"] != "203.0.113.9" {
		t.Fatalf("en-tête piégé pris pour le chemin : %+v %v", out, err)
	}
	// Un chemin avec guillemets, accolades et antislash est lu en entier.
	cfg["blocked_prefix"] = `/x"y{z}\`
	out, err = p.Call(ctx, HookRequest, RequestInput{Path: `/x"y{z}\suite`, Config: cfg})
	if err != nil || out.Action != ActionDeny {
		t.Fatalf("chemin à caractères spéciaux : %+v %v", out, err)
	}
	// Une IP qui contient guillemet et antislash ressort échappée : la sortie reste un JSON valide.
	cfg["blocked_prefix"] = "/admin"
	cfg["header"] = "X-A"
	out, err = p.Call(ctx, HookRequest, RequestInput{Path: "/", ClientIP: `a"b\c`, Config: cfg})
	if err != nil || out.SetHeaders["X-A"] != `a"b\c` {
		t.Fatalf("échappement de la sortie : %+v %v", out, err)
	}
}
