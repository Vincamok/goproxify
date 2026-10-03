// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router

import "testing"

func TestMatchLocation_Priority(t *testing.T) {
	route := &Route{
		Locations: []Location{
			{Path: "/api", PathType: "prefix", Backends: []Backend{{URL: "http://prefix"}}},
			{Path: "/api/v1", PathType: "prefix", Backends: []Backend{{URL: "http://long"}}},
			{Path: "/api/exact", PathType: "exact", Backends: []Backend{{URL: "http://exact"}}},
			{Path: `^/re/\d+$`, PathType: "regex", Backends: []Backend{{URL: "http://regex"}}},
		},
	}

	cases := []struct {
		path string
		want string
	}{
		{"/api/exact", "http://exact"},
		{"/api/v1/users", "http://long"},
		{"/api/other", "http://prefix"},
		{"/re/42", "http://regex"},
		{"/nope", ""},
	}
	for _, c := range cases {
		loc := MatchLocation(route, c.path)
		got := ""
		if loc != nil && len(loc.Backends) > 0 {
			got = loc.Backends[0].URL
		}
		if got != c.want {
			t.Fatalf("path %q: got %q want %q", c.path, got, c.want)
		}
	}
}

func TestMatchLocation_EmptyPathSkipped(t *testing.T) {
	route := &Route{
		Locations: []Location{
			{Path: "", PathType: "prefix", Backends: []Backend{{URL: "http://bad"}}},
			{Path: "/ok", PathType: "prefix", Backends: []Backend{{URL: "http://ok"}}},
		},
	}
	loc := MatchLocation(route, "/ok/x")
	if loc == nil || loc.Backends[0].URL != "http://ok" {
		t.Fatalf("expected /ok location, got %#v", loc)
	}
	if MatchLocation(route, "/elsewhere") != nil {
		t.Fatal("empty path must not match everything")
	}
}

func TestMergeLocation_Backends(t *testing.T) {
	route := &Route{
		ID:       "r1",
		Backends: []Backend{{URL: "http://main"}},
	}
	loc := &Location{
		Path:     "/api",
		Backends: []Backend{{URL: "http://loc"}},
	}
	merged := MergeLocation(route, loc)
	if len(merged.Backends) != 1 || merged.Backends[0].URL != "http://loc" {
		t.Fatalf("backends = %#v", merged.Backends)
	}
	if len(route.Backends) != 1 || route.Backends[0].URL != "http://main" {
		t.Fatal("original route mutated")
	}
	if merged.ID != "r1" {
		t.Fatalf("id = %q", merged.ID)
	}
}

func TestStripPathPrefix(t *testing.T) {
	cases := []struct{ path, prefix, want string }{
		{"/admin", "/admin", "/"},
		{"/admin/", "/admin", "/"},
		{"/admin/users", "/admin", "/users"},
		{"/administrator", "/admin", "/administrator"},
		{"/app", "/admin", "/app"},
		{"/", "/admin", "/"},
	}
	for _, c := range cases {
		got := StripPathPrefix(c.path, c.prefix)
		if got != c.want {
			t.Fatalf("StripPathPrefix(%q,%q)=%q want %q", c.path, c.prefix, got, c.want)
		}
	}
}

func TestApplyPathRewrite(t *testing.T) {
	cases := []struct {
		path, pattern, tmpl, want string
	}{
		{"/old/foo/bar", `^/old/(.*)$`, "/new/$1", "/new/foo/bar"},
		{"/api/v1/users", `^/api/(v\d+)/(.*)$`, "/backend/$2?version=$1", "/backend/users?version=v1"},
		{"/no-match", `^/api/(.*)$`, "/new/$1", "/no-match"},
		{"/a/b", `^/a/(.+)$`, "/$1", "/b"},
	}
	for _, c := range cases {
		got := ApplyPathRewrite(c.path, c.pattern, c.tmpl)
		if got != c.want {
			t.Errorf("ApplyPathRewrite(%q,%q,%q)=%q want %q", c.path, c.pattern, c.tmpl, got, c.want)
		}
	}
}

func TestMergeLocation_PathRewrite(t *testing.T) {
	route := &Route{ID: "r1"}
	loc := &Location{Path: `^/old/(.*)$`, PathType: "regex", PathRewrite: "/new/$1"}
	merged := MergeLocation(route, loc)
	if merged.PathRewrite != "/new/$1" {
		t.Fatalf("PathRewrite = %q", merged.PathRewrite)
	}
	if merged.PathRewritePattern != `^/old/(.*)$` {
		t.Fatalf("PathRewritePattern = %q", merged.PathRewritePattern)
	}
	// non-regex location must not set PathRewrite
	loc2 := &Location{Path: "/prefix", PathType: "prefix", PathRewrite: "/new/$1"}
	merged2 := MergeLocation(route, loc2)
	if merged2.PathRewrite != "" {
		t.Fatalf("expected empty PathRewrite for prefix loc, got %q", merged2.PathRewrite)
	}
}

func TestMergeLocation_StripPrefix(t *testing.T) {
	route := &Route{ID: "r1", StripPrefix: "/stale"}
	loc := &Location{Path: "/admin", StripPrefix: true}
	merged := MergeLocation(route, loc)
	if merged.StripPrefix != "/admin" {
		t.Fatalf("StripPrefix = %q", merged.StripPrefix)
	}
	loc2 := &Location{Path: "/api"}
	merged2 := MergeLocation(route, loc2)
	if merged2.StripPrefix != "" {
		t.Fatalf("expected clear strip, got %q", merged2.StripPrefix)
	}
}

func TestMatchLocation_CaseFold(t *testing.T) {
	yes, no := true, false
	route := &Route{Locations: []Location{
		{Path: "/api/v1/admin", Auth: &SSOConfig{}, Backends: []Backend{{URL: "http://prot"}}},
		{Path: "/open", Backends: []Backend{{URL: "http://open"}}},
		{Path: "/ex", PathType: "exact", RateLimit: &RateLimitConfig{}, Backends: []Backend{{URL: "http://ex"}}},
		{Path: "/opt", CaseInsensitive: &yes, Backends: []Backend{{URL: "http://opt"}}},
		{Path: "/strict", CaseInsensitive: &no, Auth: &SSOConfig{}, Backends: []Backend{{URL: "http://strict"}}},
		{Path: `^/Re/\d+$`, PathType: "regex", Auth: &SSOConfig{}, Backends: []Backend{{URL: "http://re"}}},
	}}
	cases := map[string]string{
		"/api/v1/admin/x": "http://prot",
		"/API/V1/ADMIN/x": "http://prot",
		"/Api/v1/Admin":   "http://prot",
		"/open/x":         "http://open",
		"/OPEN/x":         "",
		"/EX":             "http://ex",
		"/ex/more":        "",
		"/OPT/a":          "http://opt",
		"/strict/a":       "http://strict",
		"/STRICT/a":       "",
		"/Re/1":           "http://re",
		"/re/1":           "",
	}
	for p, want := range cases {
		got := ""
		if loc := MatchLocation(route, p); loc != nil {
			got = loc.Backends[0].URL
		}
		if got != want {
			t.Errorf("path %q: got %q want %q", p, got, want)
		}
	}
}

func TestStripPathPrefixFold(t *testing.T) {
	cases := [][3]string{
		{"/API/x", "/api", "/x"},
		{"/Api", "/api", "/"},
		{"/APIX/x", "/api", "/APIX/x"},
		{"/other", "/api", "/other"},
	}
	for _, c := range cases {
		if got := StripPathPrefixFold(c[0], c[1]); got != c[2] {
			t.Errorf("%q/%q: got %q want %q", c[0], c[1], got, c[2])
		}
	}
	route := &Route{}
	m := MergeLocation(route, &Location{Path: "/admin", StripPrefix: true, Auth: &SSOConfig{}})
	if !m.StripPrefixFold {
		t.Error("StripPrefixFold attendu pour une location protégée")
	}
	m = MergeLocation(route, &Location{Path: "/admin", StripPrefix: true})
	if m.StripPrefixFold {
		t.Error("StripPrefixFold inattendu pour une location non protégée")
	}
}
