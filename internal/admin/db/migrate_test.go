// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package db

import (
	"path/filepath"
	"testing"
)

func TestAutomationTablesReplaceLegacyEngines(t *testing.T) {
	path := filepath.Join(t.TempDir(), "admin.db")
	d, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := d.Exec(`CREATE TABLE rules_engine_rules (id TEXT PRIMARY KEY)`); err != nil {
		t.Fatal(err)
	}
	d.Close()
	d, err = Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer d.Close()
	for _, table := range []string{"flows", "flow_state", "flow_versions", "flow_runs", "flow_run_steps", "automation_silences"} {
		if _, err := d.Exec(`SELECT COUNT(*) FROM ` + table); err != nil {
			t.Errorf("%s : %v", table, err)
		}
	}
	if _, err := d.Exec(`SELECT COUNT(*) FROM rules_engine_rules`); err == nil {
		t.Error("table de l'ancien moteur de règles conservée")
	}
}
