// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package gdpr

import (
	"bytes"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestEnsureKeyIsStable(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	k1, err := EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	k2, err := EnsureKey(db)
	if err != nil {
		t.Fatal(err)
	}
	if len(k1) != 32 || !bytes.Equal(k1, k2) {
		t.Fatalf("clé instable ou de mauvaise taille : %d octets, égales=%v", len(k1), bytes.Equal(k1, k2))
	}
}
