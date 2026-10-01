// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"path/filepath"
	"testing"
)

func TestFreshDatabaseHasRequireApprovalAfterFirstOpen(t *testing.T) {
	d, err := Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	if _, err := d.Exec(`SELECT require_approval FROM rules_engine_rules`); err != nil {
		t.Fatal(err)
	}
}
