// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"path/filepath"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestControlEndpointFromRaft(t *testing.T) {
	cases := []struct {
		in   string
		want string
		ok   bool
	}{
		{"http://192.0.2.20:8002", "http://192.0.2.20:8000", true},
		{"http://backup:8002", "http://backup:8000", true},
		{"https://edge-b.example.com:8002", "https://edge-b.example.com:8000", true},
		{"192.0.2.20:8002", "http://192.0.2.20:8000", true},
		{"http://[2001:db8::1]:8002", "http://[2001:db8::1]:8000", true},
		{"", "", false},
		{"   ", "", false},
		{"http://:8002", "", false},
	}
	for _, tc := range cases {
		got, ok := controlEndpointFromRaft(tc.in)
		if got != tc.want || ok != tc.ok {
			t.Errorf("controlEndpointFromRaft(%q) = %q, %v ; attendu %q, %v", tc.in, got, ok, tc.want, tc.ok)
		}
	}
}

func TestNodeReportedHeartbeatMatchesDisplayName(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO nodes (id, node_name, display_name, role) VALUES ('n1','goproxify-core','frontal','edge')`); err != nil {
		t.Fatal(err)
	}
	m := &Manager{db: db}
	for name, want := range map[string]bool{"goproxify-core": true, "frontal": true, "autre": false} {
		if got := m.nodeReportedHeartbeat(context.Background(), name); got != want {
			t.Errorf("nodeReportedHeartbeat(%q) = %v ; attendu %v", name, got, want)
		}
	}
}
