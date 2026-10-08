// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"context"
	"testing"

	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

func benchPlugin(b *testing.B) *Plugin {
	b.Helper()
	m := manifest()
	p, err := Load(context.Background(), m, pt.Static(`{"action":"allow"}`), "", nil)
	if err != nil {
		b.Fatal(err)
	}
	b.Cleanup(func() { p.Close(context.Background()) })
	return p
}

var benchInput = RequestInput{
	Method: "GET", Host: "app.example.fr", Path: "/api/v1/items", Query: "page=2",
	Headers:  map[string][]string{"User-Agent": {"curl/8"}, "Accept": {"*/*"}, "Authorization": {"Bearer x"}},
	ClientIP: "203.0.113.9",
}

// BenchmarkCall mesure le coût d'un appel complet : instanciation, sérialisation, hook, lecture.
func BenchmarkCall(b *testing.B) {
	p := benchPlugin(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := p.Call(ctx, HookRequest, benchInput); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkCallParallel(b *testing.B) {
	p := benchPlugin(b)
	ctx := context.Background()
	b.ReportAllocs()
	b.ResetTimer()
	b.RunParallel(func(pb *testing.PB) {
		for pb.Next() {
			if _, err := p.Call(ctx, HookRequest, benchInput); err != nil {
				b.Fatal(err)
			}
		}
	})
}
