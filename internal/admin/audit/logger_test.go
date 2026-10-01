// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"path/filepath"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestLogIsSearchable(t *testing.T) {
	d, err := db.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	l := New(d, 90)

	l.Log(context.Background(), Event{Action: "login", Actor: "alice@example.com", UserID: "u1", IP: "203.0.113.7"})
	l.Log(context.Background(), Event{Action: "delete_token", Actor: "bob", ResourceType: "token", ResourceID: "t42", Severity: Warning})

	entries, total, err := l.Search(SearchParams{})
	if err != nil {
		t.Fatal(err)
	}
	if total != 2 || len(entries) != 2 {
		t.Fatalf("attendu 2 entrées, obtenu total=%d len=%d", total, len(entries))
	}
	byAction := map[string]Entry{}
	for _, e := range entries {
		byAction[e.Action] = e
	}
	if e := byAction["login"]; e.Actor != "alice@example.com" || e.UserID != "u1" || e.IP != "203.0.113.7" || e.Component != "admin" || e.Severity != "info" {
		t.Errorf("entrée login inattendue : %+v", e)
	}
	if e := byAction["delete_token"]; e.ResourceType != "token" || e.ResourceID != "t42" || e.Severity != "warning" {
		t.Errorf("entrée delete_token inattendue : %+v", e)
	}

	var res string
	if err := d.QueryRow(`SELECT resource FROM audit_log WHERE action='delete_token'`).Scan(&res); err != nil {
		t.Fatal(err)
	}
	if res != "token:t42" {
		t.Errorf("resource = %q, attendu %q", res, "token:t42")
	}
}

func TestResource(t *testing.T) {
	for _, c := range []struct{ typ, id, want string }{
		{"", "", ""},
		{"proxy", "", "proxy"},
		{"", "p1", "p1"},
		{"proxy", "p1", "proxy:p1"},
	} {
		if got := resource(c.typ, c.id); got != c.want {
			t.Errorf("resource(%q, %q) = %q, attendu %q", c.typ, c.id, got, c.want)
		}
	}
}
