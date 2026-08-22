// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package labels

import (
	"net"
	"net/url"
	"strings"
)

// HostRef is a public hostname extracted from goproxify.host (CSV).
type HostRef struct {
	Host string // lowercase hostname, no scheme/port
	Path string // empty, or a prefix like /admin (no trailing slash)
}

// ParseHostCSV splits goproxify.host and normalizes each entry.
// Accepts hostnames, host:port, https://host/path, and mixed CSV.
func ParseHostCSV(raw string) []HostRef {
	if strings.TrimSpace(raw) == "" {
		return nil
	}
	parts := strings.Split(raw, ",")
	out := make([]HostRef, 0, len(parts))
	seenHost := map[string]struct{}{}
	seenPath := map[string]struct{}{}
	for _, p := range parts {
		host, path := ParseHostEntry(p)
		if host == "" {
			continue
		}
		if _, ok := seenHost[host]; !ok {
			seenHost[host] = struct{}{}
			out = append(out, HostRef{Host: host, Path: path})
			if path != "" {
				seenPath[path] = struct{}{}
			}
			continue
		}
		if path == "" {
			continue
		}
		if _, ok := seenPath[path]; ok {
			continue
		}
		seenPath[path] = struct{}{}
		out = append(out, HostRef{Host: host, Path: path})
	}
	return out
}

// ParseHostEntry extracts hostname + optional path from a single label value.
func ParseHostEntry(raw string) (host, path string) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", ""
	}
	if i := strings.Index(raw, "://"); i >= 0 {
		u, err := url.Parse(raw)
		if err != nil || u.Host == "" {
			raw = raw[i+3:]
		} else {
			host = strings.ToLower(u.Hostname())
			host = strings.TrimSuffix(host, ".")
			return host, cleanLabelPath(u.Path)
		}
	}
	rest := raw
	if slash := strings.Index(rest, "/"); slash >= 0 {
		path = cleanLabelPath(rest[slash:])
		rest = rest[:slash]
	}
	host = strings.TrimSpace(rest)
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}
	host = strings.Trim(host, "[]")
	host = strings.ToLower(strings.TrimSpace(host))
	host = strings.TrimSuffix(host, ".")
	return host, path
}

func cleanLabelPath(p string) string {
	p = strings.TrimSpace(p)
	if p == "" || p == "/" {
		return ""
	}
	if !strings.HasPrefix(p, "/") {
		p = "/" + p
	}
	if i := strings.IndexAny(p, "?#"); i >= 0 {
		p = p[:i]
	}
	p = strings.TrimRight(p, "/")
	if p == "" {
		return ""
	}
	return p
}

// UniqueHosts returns primary host + aliases from parsed refs.
func UniqueHosts(refs []HostRef) (host string, aliases []string) {
	if len(refs) == 0 {
		return "", nil
	}
	host = refs[0].Host
	for _, r := range refs[1:] {
		if r.Host == "" || r.Host == host {
			continue
		}
		dup := false
		for _, a := range aliases {
			if a == r.Host {
				dup = true
				break
			}
		}
		if !dup {
			aliases = append(aliases, r.Host)
		}
	}
	return host, aliases
}

// UniquePaths returns non-root paths in first-seen order.
func UniquePaths(refs []HostRef) []string {
	var out []string
	seen := map[string]struct{}{}
	for _, r := range refs {
		if r.Path == "" {
			continue
		}
		if _, ok := seen[r.Path]; ok {
			continue
		}
		seen[r.Path] = struct{}{}
		out = append(out, r.Path)
	}
	return out
}
