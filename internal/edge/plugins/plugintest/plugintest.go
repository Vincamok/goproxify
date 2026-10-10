// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

// Package plugintest assemble de petits modules WebAssembly pour les tests des plugins : de quoi
// exercer le moteur sans chaine de compilation.
package plugintest

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

func Str(s string) []byte { return append(uleb(uint64(len(s))), s...) }

func section(id byte, content []byte) []byte {
	return append(append([]byte{id}, uleb(uint64(len(content)))...), content...)
}

type Fn struct {
	Typ    int
	Body   []byte // instructions, sans `end` final
	Locals []byte // déclarations de locales déjà encodées (nil = aucune)
}

type Spec struct {
	Imports   [][]byte // entrées d'import déjà encodées
	Funcs     []Fn     // fonctions définies (indices après les Imports)
	MemMin    uint64
	ExportsFn map[string]int
	DataAt    int
	Data      []byte
	Segments  []Segment // segments de données supplémentaires
}

// Segment est un segment de données actif de la mémoire 0.
type Segment struct {
	At   int
	Data []byte
}

var (
	typeAlloc = append([]byte{0x60}, append(vec([]byte{0x7f}), vec([]byte{0x7f})...)...)               // (i32)->i32
	typeHook  = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}), vec([]byte{0x7e})...)...) // (i32,i32)->i64
	typeLog   = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}), vec()...)...)             // (i32,i32)->()
)

func I64(v int64) []byte { return append([]byte{0x42}, sleb(v)...) }
func I32(v int32) []byte { return append([]byte{0x41}, sleb(int64(v))...) }

func (s Spec) Build() []byte {
	b := []byte("\x00asm\x01\x00\x00\x00")
	b = append(b, section(1, vec(typeAlloc, typeHook, typeLog, typeIncr, typeGet, typeSet, typeFetch))...)
	if len(s.Imports) > 0 {
		b = append(b, section(2, vec(s.Imports...))...)
	}
	var fnTypes [][]byte
	for _, f := range s.Funcs {
		fnTypes = append(fnTypes, uleb(uint64(f.Typ)))
	}
	b = append(b, section(3, vec(fnTypes...))...)
	b = append(b, section(5, vec(append([]byte{0x00}, uleb(s.MemMin)...)))...)
	var exps [][]byte
	for name, idx := range s.ExportsFn {
		exps = append(exps, append(Str(name), append([]byte{0x00}, uleb(uint64(idx))...)...))
	}
	exps = append(exps, append(Str("memory"), 0x02, 0x00))
	b = append(b, section(7, vec(exps...))...)
	var bodies [][]byte
	for _, f := range s.Funcs {
		decl := f.Locals
		if decl == nil {
			decl = []byte{0x00} // aucune déclaration de locale
		}
		Body := append(append([]byte{}, decl...), f.Body...)
		Body = append(Body, 0x0b)
		bodies = append(bodies, append(uleb(uint64(len(Body))), Body...))
	}
	b = append(b, section(10, vec(bodies...))...)
	segs := s.Segments
	if len(s.Data) > 0 {
		segs = append([]Segment{{At: s.DataAt, Data: s.Data}}, segs...)
	}
	if len(segs) > 0 {
		var encoded [][]byte
		for _, sg := range segs {
			seg := append([]byte{0x00}, I32(int32(sg.At))...)
			seg = append(seg, 0x0b)
			seg = append(seg, uleb(uint64(len(sg.Data)))...)
			seg = append(seg, sg.Data...)
			encoded = append(encoded, seg)
		}
		b = append(b, section(11, vec(encoded...))...)
	}
	return b
}

const dataAtOffset = 32768

// Static répond toujours la même sortie JSON. Les entrées sont écrites en 1024.
func Static(out string) []byte {
	packed := int64(dataAtOffset)<<32 | int64(len(out))
	return Spec{
		MemMin: 2,
		Funcs: []Fn{
			{Typ: 0, Body: I32(1024)}, // alloc
			{Typ: 1, Body: I64(packed)},
			{Typ: 1, Body: I64(packed)},
			{Typ: 1, Body: I64(packed)},
			{Typ: 1, Body: I64(packed)},
			{Typ: 1, Body: I64(packed)},
		},
		ExportsFn: map[string]int{"alloc": 0, "on_request": 1, "on_response": 2, "on_request_body": 3, "on_response_body": 4, "on_connect": 5},
		DataAt:    dataAtOffset, Data: []byte(out),
	}.Build()
}

func Loop() []byte {
	return Spec{
		MemMin: 2,
		Funcs: []Fn{
			{Typ: 0, Body: I32(1024)},
			{Typ: 1, Body: []byte{0x03, 0x40, 0x0c, 0x00, 0x0b, 0x42, 0x00}}, // loop { br 0 } ; i64.const 0
		},
		ExportsFn: map[string]int{"alloc": 0, "on_request": 1},
	}.Build()
}

func Trap() []byte {
	return Spec{
		MemMin:    2,
		Funcs:     []Fn{{Typ: 0, Body: I32(1024)}, {Typ: 1, Body: []byte{0x00, 0x42, 0x00}}}, // unreachable
		ExportsFn: map[string]int{"alloc": 0, "on_request": 1},
	}.Build()
}

// Log journalise son entrée via gpx.log puis laisse passer.
func Log() []byte {
	imp := append(Str("gpx"), append(Str("log"), 0x00, 0x02)...) // fonction de type 2
	call := []byte{0x20, 0x00, 0x20, 0x01, 0x10, 0x00, 0x42, 0x00}
	return Spec{
		Imports:   [][]byte{imp},
		MemMin:    2,
		Funcs:     []Fn{{Typ: 0, Body: I32(1024)}, {Typ: 1, Body: call}, {Typ: 1, Body: call}, {Typ: 1, Body: call}, {Typ: 1, Body: call}},
		ExportsFn: map[string]int{"alloc": 1, "on_request": 2, "on_request_body": 3, "on_response_body": 4, "on_connect": 5},
	}.Build()
}
