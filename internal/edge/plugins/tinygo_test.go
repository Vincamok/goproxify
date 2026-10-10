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
