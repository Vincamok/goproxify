// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugintest

// Modules de test qui appellent les fonctions de l'hôte (état clé/valeur, réseau).

var (
	typeIncr  = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}, []byte{0x7e}, []byte{0x7f}), vec([]byte{0x7e})...)...)               // (i32,i32,i64,i32)->i64
	typeGet   = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}), vec([]byte{0x7e})...)...)                                           // (i32,i32)->i64
	typeSet   = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}, []byte{0x7f}, []byte{0x7f}, []byte{0x7f}), vec([]byte{0x7f})...)...) // (i32,i32,i32,i32,i32)->i32
	typeFetch = append([]byte{0x60}, append(vec([]byte{0x7f}, []byte{0x7f}), vec([]byte{0x7e})...)...)                                           // (i32,i32)->i64
)

const (
	kindFn    = 0x00
	denyAt    = 32768
	allowAt   = 33024
	keyAt     = 40000
	valueAt   = 40100
	requestAt = 41000
)

func imp(module, name string, typ int) []byte {
	return append(append(Str(module), Str(name)...), kindFn, byte(typ))
}

func packed(at int, s string) int64 { return int64(at)<<32 | int64(len(s)) }

const (
	allowJSON = `{"action":"allow"}`
	denyJSON  = `{"action":"deny","status":429,"body":"trop de requêtes"}`
)

// KVLimiter incrémente le compteur « ctr » (fenêtre de 60 s) à chaque appel de on_request, refuse (429) dès
// que le compteur dépasse limit et laisse passer sinon : une limitation de débit écrite avec gpx.kv_incr.
func KVLimiter(limit int64) []byte {
	incr := []byte{}
	incr = append(incr, I32(keyAt)...)
	incr = append(incr, I32(3)...)
	incr = append(incr, I64(1)...)
	incr = append(incr, I32(60000)...)
	incr = append(incr, 0x10, 0x00) // call kv_incr (import 0)
	incr = append(incr, I64(limit)...)
	incr = append(incr, 0x55)       // i64.gt_s
	incr = append(incr, 0x04, 0x7e) // if (result i64)
	incr = append(incr, I64(packed(denyAt, denyJSON))...)
	incr = append(incr, 0x05) // else
	incr = append(incr, I64(packed(allowAt, allowJSON))...)
	incr = append(incr, 0x0b) // end
	return Spec{
		Imports:   [][]byte{imp("gpx", "kv_incr", 3)},
		MemMin:    2,
		Funcs:     []Fn{{Typ: 0, Body: I32(1024)}, {Typ: 1, Body: incr}},
		ExportsFn: map[string]int{"alloc": 1, "on_request": 2},
		Segments: []Segment{
			{At: denyAt, Data: []byte(denyJSON)},
			{At: allowAt, Data: []byte(allowJSON)},
			{At: keyAt, Data: []byte("ctr")},
		},
	}.Build()
}

// KVRoundTrip enregistre la sortie JSON `value` sous la clé « k » avec gpx.kv_set, puis la relit avec
// gpx.kv_get et la renvoie comme décision : la décision n'existe que si l'état a bien fait l'aller-retour.
func KVRoundTrip(value string) []byte {
	body := []byte{}
	body = append(body, I32(keyAt)...)
	body = append(body, I32(1)...)
	body = append(body, I32(valueAt)...)
	body = append(body, I32(int32(len(value)))...)
	body = append(body, I32(0)...)
	body = append(body, 0x10, 0x00) // call kv_set (import 0)
	body = append(body, 0x1a)       // drop
	body = append(body, I32(keyAt)...)
	body = append(body, I32(1)...)
	body = append(body, 0x10, 0x01) // call kv_get (import 1)
	return Spec{
		Imports:   [][]byte{imp("gpx", "kv_set", 5), imp("gpx", "kv_get", 4)},
		MemMin:    2,
		Funcs:     []Fn{{Typ: 0, Body: I32(1024)}, {Typ: 1, Body: body}},
		ExportsFn: map[string]int{"alloc": 2, "on_request": 3},
		Segments:  []Segment{{At: keyAt, Data: []byte("k")}, {At: valueAt, Data: []byte(value)}},
	}.Build()
}

// Fetch appelle gpx.http_fetch avec la requête JSON `request` et journalise la réponse avec gpx.log, puis
// laisse passer. Le journal est le seul moyen, pour un test, de lire ce que le plugin a reçu.
func Fetch(request string) []byte {
	body := []byte{}
	body = append(body, I32(requestAt)...)
	body = append(body, I32(int32(len(request)))...)
	body = append(body, 0x10, 0x01) // call http_fetch (import 1)
	body = append(body, 0x22, 0x02) // local.tee 2 (après les deux paramètres)
	body = append(body, I64(32)...)
	body = append(body, 0x88)       // i64.shr_u
	body = append(body, 0xa7)       // i32.wrap_i64
	body = append(body, 0x20, 0x02) // local.get 2
	body = append(body, 0xa7)       // i32.wrap_i64
	body = append(body, 0x10, 0x00) // call log (import 0)
	body = append(body, I64(0)...)
	return Spec{
		Imports:   [][]byte{imp("gpx", "log", 2), imp("gpx", "http_fetch", 6)},
		MemMin:    2,
		Funcs:     []Fn{{Typ: 0, Body: I32(1024)}, {Typ: 1, Body: body, Locals: []byte{0x01, 0x01, 0x7e}}},
		ExportsFn: map[string]int{"alloc": 2, "on_request": 3},
		Segments:  []Segment{{At: requestAt, Data: []byte(request)}},
	}.Build()
}
