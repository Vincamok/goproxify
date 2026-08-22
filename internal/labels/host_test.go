// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package labels

import "testing"

func TestParseHostEntry(t *testing.T) {
	cases := []struct {
		in, host, path string
	}{
		{"app.example.fr", "app.example.fr", ""},
		{"APP.Example.FR.", "app.example.fr", ""},
		{"https://app.example.fr", "app.example.fr", ""},
		{"https://app.example.fr/", "app.example.fr", ""},
		{"https://app.example.fr/admin", "app.example.fr", "/admin"},
		{"https://app.example.fr/admin/", "app.example.fr", "/admin"},
		{"https://app.example.fr:443/app", "app.example.fr", "/app"},
		{"app.example.fr/dashboard", "app.example.fr", "/dashboard"},
		{"*.example.fr", "*.example.fr", ""},
		{"www.example.fr:80", "www.example.fr", ""},
	}
	for _, c := range cases {
		host, path := ParseHostEntry(c.in)
		if host != c.host || path != c.path {
			t.Fatalf("%q: got %q %q, want %q %q", c.in, host, path, c.host, c.path)
		}
	}
}

func TestParseHostCSVAliasesAndPaths(t *testing.T) {
	refs := ParseHostCSV("https://a.example.fr/admin, b.example.fr, a.example.fr/app")
	host, aliases := UniqueHosts(refs)
	if host != "a.example.fr" {
		t.Fatalf("host=%q", host)
	}
	if len(aliases) != 1 || aliases[0] != "b.example.fr" {
		t.Fatalf("aliases=%#v", aliases)
	}
	paths := UniquePaths(refs)
	if len(paths) != 2 || paths[0] != "/admin" || paths[1] != "/app" {
		t.Fatalf("paths=%#v", paths)
	}
}
