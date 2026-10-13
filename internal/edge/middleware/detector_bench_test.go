// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

func BenchmarkObserveDecisions(b *testing.B) {
	next := http.HandlerFunc(func(http.ResponseWriter, *http.Request) {})
	pass := func(h http.Handler) http.Handler { return h }
	req := httptest.NewRequest(http.MethodGet, "http://bench.test/", nil)
	w := httptest.NewRecorder()
	b.Run("sans observateur", func(b *testing.B) {
		h := pass(next)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h.ServeHTTP(w, req)
		}
	})
	b.Run("avec observateur", func(b *testing.B) {
		h := observeDecisions("bench", pass)(next)
		b.ReportAllocs()
		for i := 0; i < b.N; i++ {
			h.ServeHTTP(w, req)
		}
	})
}
