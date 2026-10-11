// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package waf

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func benchInspect(b *testing.B, method, target, ct, body string) {
	e := NewEngine(nil, slog.Default())
	b.ReportAllocs()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		r := httptest.NewRequest(method, target, strings.NewReader(body))
		r.Header.Set("User-Agent", "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36")
		r.Header.Set("Accept", "text/html,application/xhtml+xml")
		if ct != "" {
			r.Header.Set("Content-Type", ct)
		}
		_ = e.Inspect(r, 1)
	}
}

func BenchmarkInspect_GETPlain(b *testing.B) {
	benchInspect(b, http.MethodGet, "/products/list?category=chairs&page=3&sort=price", "", "")
}

func BenchmarkInspect_GETEncoded(b *testing.B) {
	benchInspect(b, http.MethodGet, "/search?q=caf%C3%A9+cr%C3%A8me+br%C3%BBl%C3%A9e&page=2&filter=a%20b%20c", "", "")
}

func BenchmarkInspect_JSON2KB(b *testing.B) {
	benchInspect(b, http.MethodPost, "/api/items", "application/json", `{"name":"`+strings.Repeat("Table basse ", 150)+`","price":120}`)
}

func BenchmarkInspect_FormEncoded20KB(b *testing.B) {
	benchInspect(b, http.MethodPost, "/submit", "application/x-www-form-urlencoded", "text="+strings.Repeat("hello%20world+", 1400))
}

func BenchmarkInspect_Body200KB(b *testing.B) {
	benchInspect(b, http.MethodPost, "/upload", "application/octet-stream", strings.Repeat("A1b2C3d4 ", 22000))
}
