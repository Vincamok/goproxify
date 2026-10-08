// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

func manifest(hooks ...string) Manifest {
	if len(hooks) == 0 {
		hooks = []string{HookRequest}
	}
	return Manifest{Name: "t", Version: "1.0.0", APIVersion: APIVersion, Hooks: hooks}
}

func load(t *testing.T, m Manifest, wasm []byte) *Plugin {
	t.Helper()
	p, err := Load(context.Background(), m, wasm, "", nil)
	if err != nil {
		t.Fatalf("Load : %v", err)
	}
	t.Cleanup(func() { p.Close(context.Background()) })
	return p
}

func TestCall_DenyAndModify(t *testing.T) {
	p := load(t, manifest(HookRequest, HookResponse), pt.Static(`{"action":"deny","status":451,"body":"non"}`))
	out, err := p.Call(context.Background(), HookRequest, RequestInput{Method: "GET", Path: "/"})
	if err != nil || out.Action != ActionDeny || out.Status != 451 || out.Body != "non" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	m := load(t, manifest(HookResponse), pt.Static(`{"action":"modify","set_headers":{"X-Plugin":"ok"},"remove_headers":["Server"]}`))
	out, err = m.Call(context.Background(), HookResponse, ResponseInput{Status: 200})
	if err != nil || out.Action != ActionModify || out.SetHeaders["X-Plugin"] != "ok" || out.RemoveHeaders[0] != "Server" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestCall_DefaultsAndUndeclaredHook(t *testing.T) {
	p := load(t, manifest(), pt.Static(`{"action":"deny"}`))
	out, _ := p.Call(context.Background(), HookRequest, RequestInput{})
	if out.Status != 403 {
		t.Errorf("status par défaut = %d", out.Status)
	}
	// Un hook non déclaré est ignoré : le plugin n'est jamais appelé.
	out, err := p.Call(context.Background(), HookResponse, ResponseInput{})
	if err != nil || out.Action != ActionAllow {
		t.Errorf("hook non déclaré : %+v %v", out, err)
	}
}

func TestCall_ErrorsAreReported(t *testing.T) {
	for name, wasm := range map[string][]byte{
		"boucle infinie":   pt.Loop(),
		"trap":             pt.Trap(),
		"sortie illisible": pt.Static(`pas du json`),
		"action inconnue":  pt.Static(`{"action":"explode"}`),
		"status invalide":  pt.Static(`{"action":"deny","status":200}`),
		"en-tête injecté":  pt.Static(`{"action":"modify","set_headers":{"X-A":"v\r\nSet-Cookie: a=b"}}`),
		"en-tête interdit": pt.Static(`{"action":"modify","set_headers":{"Content-Length":"0"}}`),
		"retrait interdit": pt.Static(`{"action":"modify","remove_headers":["Host"]}`),
	} {
		m := manifest()
		m.Limits.TimeoutMs = 30
		p := load(t, m, wasm)
		if _, err := p.Call(context.Background(), HookRequest, RequestInput{}); err == nil {
			t.Errorf("%s : aucune erreur", name)
		}
	}
}

type writerFunc func([]byte) (int, error)

func (f writerFunc) Write(b []byte) (int, error) { return f(b) }

func TestCall_InputIsDelivered(t *testing.T) {
	var buf bytes.Buffer
	var mu sync.Mutex
	log := slog.New(slog.NewJSONHandler(writerFunc(func(b []byte) (int, error) {
		mu.Lock()
		defer mu.Unlock()
		return buf.Write(b)
	}), nil))
	p, err := Load(context.Background(), manifest(), pt.Log(), "", log)
	if err != nil {
		t.Fatal(err)
	}
	defer p.Close(context.Background())
	out, err := p.Call(context.Background(), HookRequest, RequestInput{Method: "POST", Host: "a.test", Path: "/x", ClientIP: "203.0.113.9", Config: map[string]any{"k": "v"}})
	if err != nil || out.Action != ActionAllow {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	mu.Lock()
	logged := buf.String()
	mu.Unlock()
	var line struct {
		Message string `json:"message"`
	}
	if err := json.Unmarshal([]byte(strings.Split(logged, "\n")[0]), &line); err != nil {
		t.Fatalf("journal = %q", logged)
	}
	var in RequestInput
	if err := json.Unmarshal([]byte(line.Message), &in); err != nil || in.Method != "POST" || in.ClientIP != "203.0.113.9" || in.Config["k"] != "v" {
		t.Fatalf("entrée reçue par le plugin = %q (%v)", line.Message, err)
	}
}

func TestLoad_Contract(t *testing.T) {
	ctx := context.Background()
	okWasm := pt.Static(`{}`)
	if _, err := Load(ctx, manifest(), okWasm, "deadbeef", nil); err == nil {
		t.Error("empreinte fausse acceptée")
	}
	p := load(t, manifest(), okWasm)
	if _, err := Load(ctx, manifest(), okWasm, p.SHA256, nil); err != nil {
		t.Errorf("empreinte exacte refusée : %v", err)
	}
	// Un hook déclaré mais non exporté.
	if _, err := Load(ctx, manifest(HookRequest, HookResponse), pt.Loop(), "", nil); err == nil {
		t.Error("hook on_response non exporté accepté")
	}
	if _, err := Load(ctx, manifest(), []byte("pas du wasm"), "", nil); err == nil {
		t.Error("module invalide accepté")
	}
	// Import hors gpx.log (WASI) refusé : aucune capacité implicite.
	wasi := append(pt.Str("wasi_snapshot_preview1"), append(pt.Str("fd_write"), 0x00, 0x02)...)
	bad := pt.Spec{Imports: [][]byte{wasi}, MemMin: 2,
		Funcs:     []pt.Fn{{Typ: 0, Body: pt.I32(1024)}, {Typ: 1, Body: pt.I64(0)}},
		ExportsFn: map[string]int{"alloc": 1, "on_request": 2}}.Build()
	if _, err := Load(ctx, manifest(), bad, "", nil); err == nil || !strings.Contains(err.Error(), "import non autorisé") {
		t.Errorf("import WASI : %v", err)
	}
	// Mémoire minimale au-delà du plafond : le plugin ne peut pas s'exécuter.
	big := pt.Spec{MemMin: 40, Funcs: []pt.Fn{{Typ: 0, Body: pt.I32(1024)}, {Typ: 1, Body: pt.I64(0)}},
		ExportsFn: map[string]int{"alloc": 0, "on_request": 1}}.Build()
	m := manifest()
	m.Limits.MemoryPages = 16
	if bp, err := Load(ctx, m, big, "", nil); err == nil {
		_, cerr := bp.Call(ctx, HookRequest, RequestInput{})
		bp.Close(ctx)
		if cerr == nil {
			t.Error("mémoire au-delà du plafond acceptée")
		}
	}
}

func TestManifestNormalize(t *testing.T) {
	good := manifest(HookRequest)
	if err := good.Normalize(); err != nil || good.OnError != OnErrorDeny || good.Limits.MemoryPages != DefaultMemoryPages || good.Limits.TimeoutMs != DefaultTimeoutMs {
		t.Fatalf("défauts : %+v %v", good, err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"nom":          func(m *Manifest) { m.Name = "Bad Name" },
		"nom vide":     func(m *Manifest) { m.Name = "" },
		"version":      func(m *Manifest) { m.Version = "" },
		"api":          func(m *Manifest) { m.APIVersion = 2 },
		"sans hook":    func(m *Manifest) { m.Hooks = nil },
		"hook inconnu": func(m *Manifest) { m.Hooks = []string{"log"} },
		"hook double":  func(m *Manifest) { m.Hooks = []string{"request", "request"} },
		"on_error":     func(m *Manifest) { m.OnError = "ignore" },
		"mémoire":      func(m *Manifest) { m.Limits.MemoryPages = MaxMemoryPages + 1 },
		"délai":        func(m *Manifest) { m.Limits.TimeoutMs = MaxTimeoutMs + 1 },
	} {
		m := manifest()
		mutate(&m)
		if err := m.Normalize(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
}
