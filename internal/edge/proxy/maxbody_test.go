// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package proxy

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestBodyTooLarge(t *testing.T) {
	h := &Handler{route: &router.Route{MaxBodySize: 10}}
	cases := []struct {
		name string
		cl   int64
		want bool
	}{
		{"declared too large", 11, true},
		{"declared ok", 10, false},
		{"chunked (unknown length)", -1, false},
	}
	for _, c := range cases {
		r := httptest.NewRequest(http.MethodPost, "/", strings.NewReader(""))
		r.ContentLength = c.cl
		if got := h.bodyTooLarge(r); got != c.want {
			t.Errorf("%s: got %v want %v", c.name, got, c.want)
		}
	}
}

func TestEffectiveMaxBodySize(t *testing.T) {
	if (&router.Route{}).EffectiveMaxBodySize() != router.DefaultMaxBodySize {
		t.Fatal("défaut attendu")
	}
	if (&router.Route{MaxBodySize: -1}).EffectiveMaxBodySize() != 0 {
		t.Fatal("illimité attendu")
	}
	if (&router.Route{MaxBodySize: 5}).EffectiveMaxBodySize() != 5 {
		t.Fatal("valeur explicite attendue")
	}
}
