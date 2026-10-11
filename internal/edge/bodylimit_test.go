// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestLimitInternalBodies(t *testing.T) {
	read := func(path string, size int) error {
		var err error
		req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(strings.Repeat("x", size)))
		req.ContentLength = -1
		limitInternalBodies(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { _, err = io.ReadAll(r.Body) })).ServeHTTP(httptest.NewRecorder(), req)
		return err
	}
	if err := read("/internal/v1/pair", maxInternalPublicBody); err != nil {
		t.Errorf("appairage à la limite : %v", err)
	}
	if err := read("/internal/v1/pair", maxInternalPublicBody+1); err == nil {
		t.Error("appairage : au-delà de 64 Kio doit être refusé")
	}
	if err := read("/internal/v1/backup/restore", 129<<20); err != nil {
		t.Errorf("la restauration (128 Mio) reste possible : %v", err)
	}
	if err := read("/internal/v1/routes", maxInternalBody+1); err == nil {
		t.Error("au-delà de 160 Mio : refusé")
	}
}
