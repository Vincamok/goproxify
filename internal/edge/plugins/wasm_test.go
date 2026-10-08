// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"log/slog"
	"strings"
	"sync"
	"testing"
)

// Assembleur WebAssembly minimal : de quoi produire des modules de test sans chaîne de compilation.

func uleb(v uint64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if v != 0 {
			out = append(out, b|0x80)
			continue
		}
		return append(out, b)
	}
}

func sleb(v int64) []byte {
	var out []byte
	for {
		b := byte(v & 0x7f)
		v >>= 7
		if (v == 0 && b&0x40 == 0) || (v == -1 && b&0x40 != 0) {
			return append(out, b)
		}
		out = append(out, b|0x80)
	}
}

func vec(items ...[]byte) []byte {
	out := uleb(uint64(len(items)))
	for _, it := range items {
		out = append(out, it...)
	}
	return out
}

func str(s string) []byte { return append(uleb(uint64(len(s))), s...) }

func section(id byte, content []byte) []byte {
	return append(append([]byte{id}, uleb(uint64(len(content)))...), content...)
}

type fn struct {
	typ  int
	body []byte // instructions, sans `end` final
}

type modSpec struct {
	imports   [][]byte // entrées d'import déjà encodées
	funcs     []fn     // fonctions définies (indices après les imports)
	memMin    uint64
	exportsFn map[string]int
	dataAt    int
	data      []byte
}

var (
	typeAlloc = append([]byte{0x60}, append(vec([]byte{0x7f}), vec([]byte{0x7f})...)...)               // (i32)->i32
	typeHook  = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}), vec([]byte{0x7e})...)...) // (i32,i32)->i64
	typeLog   = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}), vec()...)...)             // (i32,i32)->()
)

func i64Const(v int64) []byte { return append([]byte{0x42}, sleb(v)...) }
func i32Const(v int32) []byte { return append([]byte{0x41}, sleb(int64(v))...) }

func (s modSpec) build() []byte {
	b := []byte("\x00asm\x01\x00\x00\x00")
	b = append(b, section(1, vec(typeAlloc, typeHook, typeLog))...)
	if len(s.imports) > 0 {
		b = append(b, section(2, vec(s.imports...))...)
	}
	var fnTypes [][]byte
	for _, f := range s.funcs {
		fnTypes = append(fnTypes, uleb(uint64(f.typ)))
	}
	b = append(b, section(3, vec(fnTypes...))...)
	b = append(b, section(5, vec(append([]byte{0x00}, uleb(s.memMin)...)))...)
	var exps [][]byte
	for name, idx := range s.exportsFn {
		exps = append(exps, append(str(name), append([]byte{0x00}, uleb(uint64(idx))...)...))
	}
	exps = append(exps, append(str("memory"), 0x02, 0x00))
	b = append(b, section(7, vec(exps...))...)
	var bodies [][]byte
	for _, f := range s.funcs {
		body := append([]byte{0x00}, f.body...) // aucune déclaration de locale
		body = append(body, 0x0b)
		bodies = append(bodies, append(uleb(uint64(len(body))), body...))
	}
	b = append(b, section(10, vec(bodies...))...)
	if len(s.data) > 0 {
		seg := append([]byte{0x00}, i32Const(int32(s.dataAt))...)
		seg = append(seg, 0x0b)
		seg = append(seg, uleb(uint64(len(s.data)))...)
		seg = append(seg, s.data...)
		b = append(b, section(11, vec(seg))...)
	}
	return b
}

const dataAt = 32768

// staticPlugin répond toujours la même sortie JSON. Les entrées sont écrites en 1024.
func staticPlugin(out string) []byte {
	packed := int64(dataAt)<<32 | int64(len(out))
	return modSpec{
		memMin: 2,
		funcs: []fn{
			{typ: 0, body: i32Const(1024)}, // alloc
			{typ: 1, body: i64Const(packed)},
			{typ: 1, body: i64Const(packed)},
		},
		exportsFn: map[string]int{"alloc": 0, "on_request": 1, "on_response": 2},
		dataAt:    dataAt, data: []byte(out),
	}.build()
}

func loopPlugin() []byte {
	return modSpec{
		memMin: 2,
		funcs: []fn{
			{typ: 0, body: i32Const(1024)},
			{typ: 1, body: []byte{0x03, 0x40, 0x0c, 0x00, 0x0b, 0x42, 0x00}}, // loop { br 0 } ; i64.const 0
		},
		exportsFn: map[string]int{"alloc": 0, "on_request": 1},
	}.build()
}

func trapPlugin() []byte {
	return modSpec{
		memMin:    2,
		funcs:     []fn{{typ: 0, body: i32Const(1024)}, {typ: 1, body: []byte{0x00, 0x42, 0x00}}}, // unreachable
		exportsFn: map[string]int{"alloc": 0, "on_request": 1},
	}.build()
}

// logPlugin journalise son entrée via gpx.log puis laisse passer.
func logPlugin() []byte {
	imp := append(str("gpx"), append(str("log"), 0x00, 0x02)...) // fonction de type 2
	call := []byte{0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x42, 0x00}
	return modSpec{
		imports:   [][]byte{imp},
		memMin:    2,
		funcs:     []fn{{typ: 0, body: i32Const(1024)}, {typ: 1, body: call}},
		exportsFn: map[string]int{"alloc": 1, "on_request": 2},
	}.build()
}

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
	p := load(t, manifest(HookRequest, HookResponse), staticPlugin(`{"action":"deny","status":451,"body":"non"}`))
	out, err := p.Call(context.Background(), HookRequest, RequestInput{Method: "GET", Path: "/"})
	if err != nil || out.Action != ActionDeny || out.Status != 451 || out.Body != "non" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
	m := load(t, manifest(HookResponse), staticPlugin(`{"action":"modify","set_headers":{"X-Plugin":"ok"},"remove_headers":["Server"]}`))
	out, err = m.Call(context.Background(), HookResponse, ResponseInput{Status: 200})
	if err != nil || out.Action != ActionModify || out.SetHeaders["X-Plugin"] != "ok" || out.RemoveHeaders[0] != "Server" {
		t.Fatalf("out=%+v err=%v", out, err)
	}
}

func TestCall_DefaultsAndUndeclaredHook(t *testing.T) {
	p := load(t, manifest(), staticPlugin(`{"action":"deny"}`))
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
		"boucle infinie":   loopPlugin(),
		"trap":             trapPlugin(),
		"sortie illisible": staticPlugin(`pas du json`),
		"action inconnue":  staticPlugin(`{"action":"explode"}`),
		"status invalide":  staticPlugin(`{"action":"deny","status":200}`),
		"en-tête injecté":  staticPlugin(`{"action":"modify","set_headers":{"X-A":"v\r\nSet-Cookie: a=b"}}`),
		"en-tête interdit": staticPlugin(`{"action":"modify","set_headers":{"Content-Length":"0"}}`),
		"retrait interdit": staticPlugin(`{"action":"modify","remove_headers":["Host"]}`),
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
	p, err := Load(context.Background(), manifest(), logPlugin(), "", log)
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
	okWasm := staticPlugin(`{}`)
	if _, err := Load(ctx, manifest(), okWasm, "deadbeef", nil); err == nil {
		t.Error("empreinte fausse acceptée")
	}
	p := load(t, manifest(), okWasm)
	if _, err := Load(ctx, manifest(), okWasm, p.SHA256, nil); err != nil {
		t.Errorf("empreinte exacte refusée : %v", err)
	}
	// Un hook déclaré mais non exporté.
	if _, err := Load(ctx, manifest(HookRequest, HookResponse), loopPlugin(), "", nil); err == nil {
		t.Error("hook on_response non exporté accepté")
	}
	if _, err := Load(ctx, manifest(), []byte("pas du wasm"), "", nil); err == nil {
		t.Error("module invalide accepté")
	}
	// Import hors gpx.log (WASI) refusé : aucune capacité implicite.
	wasi := append(str("wasi_snapshot_preview1"), append(str("fd_write"), 0x00, 0x02)...)
	bad := modSpec{imports: [][]byte{wasi}, memMin: 2,
		funcs:     []fn{{typ: 0, body: i32Const(1024)}, {typ: 1, body: i64Const(0)}},
		exportsFn: map[string]int{"alloc": 1, "on_request": 2}}.build()
	if _, err := Load(ctx, manifest(), bad, "", nil); err == nil || !strings.Contains(err.Error(), "import non autorisé") {
		t.Errorf("import WASI : %v", err)
	}
	// Mémoire minimale au-delà du plafond : le plugin ne peut pas s'exécuter.
	big := modSpec{memMin: 40, funcs: []fn{{typ: 0, body: i32Const(1024)}, {typ: 1, body: i64Const(0)}},
		exportsFn: map[string]int{"alloc": 0, "on_request": 1}}.build()
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
