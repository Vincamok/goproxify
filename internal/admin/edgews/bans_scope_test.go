// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"
	"log/slog"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/archstore"
)

func TestLoadActiveBansFollowsTargetScope(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	for id, scope := range map[string]string{
		"global": "", "paris": "paris", "lyon": "lyon", "ha": "group:ha-1", "autre": "group:ha-2", "idparis": "tok-paris",
	} {
		if _, err := db.Exec(`INSERT INTO security_bans (id, ip, target_scope) VALUES (?, '203.0.113.9', ?)`, id, scope); err != nil {
			t.Fatal(err)
		}
	}
	arch := archstore.New(t.TempDir())
	for _, n := range []archstore.NodeEntry{
		{ID: "tok-paris", Role: "edge", Name: "paris", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
		{ID: "tok-lyon", Role: "edge", Name: "lyon", Config: json.RawMessage(`{"cluster": false}`)},
	} {
		if err := arch.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	m := NewManager("", db, slog.Default())
	m.SetArchStore(arch)

	ids := func(e *edgeEntry) string {
		list, err := m.loadActiveBans(context.Background(), e)
		if err != nil {
			t.Fatal(err)
		}
		var out []string
		for _, b := range list {
			out = append(out, b.ID)
		}
		sort.Strings(out)
		return strings.Join(out, ",")
	}
	if got := ids(&edgeEntry{id: "tok-paris", nodeName: "paris"}); got != "global,ha,idparis,paris" {
		t.Errorf("paris (groupe ha-1) : %s", got)
	}
	if got := ids(&edgeEntry{id: "tok-lyon", nodeName: "lyon"}); got != "global,lyon" {
		t.Errorf("lyon : %s", got)
	}
	if got := ids(nil); got != "global" {
		t.Errorf("sans passerelle : %s", got)
	}
}
