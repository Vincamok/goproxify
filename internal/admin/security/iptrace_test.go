// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"net/netip"
	"testing"
	"time"
)

func TestTraceRangeCoversEveryAddressOfThePrefix(t *testing.T) {
	for _, c := range []struct {
		cidr string
		in   []string
		out  []string
	}{
		{"203.0.113.0/24", []string{"203.0.113.7", "203.0.113.255"}, []string{"203.0.114.1", "20.3.113.7"}},
		{"203.0.0.0/12", []string{"203.5.1.1"}, []string{"204.0.0.1"}},
		{"198.51.100.4/32", []string{"198.51.100.4"}, []string{"198.51.100.40", "198.51.100.5"}},
		{"2001:db8::/32", []string{"2001:db8::1", "2001:db8:0:1::2", "2001:db8:ffff::1"}, []string{"2001:db9::1"}},
		{"2001:db8:0:1::/64", []string{"2001:db8:0:1::5", "2001:db8:0:1:2::3"}, []string{"2001:db8:0:2::1"}},
	} {
		p, err := ParseTraceTarget(c.cidr)
		if err != nil {
			t.Fatal(err)
		}
		lo, hi, ok := TraceIPRange(p)
		if !ok {
			t.Fatalf("%s : aucune plage", c.cidr)
		}
		inRange := func(s string) bool { return s >= lo && s < hi }
		for _, ip := range c.in {
			if !inRange(netip.MustParseAddr(ip).String()) {
				t.Errorf("%s : %s hors de [%q,%q)", c.cidr, ip, lo, hi)
			}
			if !TraceMatch(p, ip) {
				t.Errorf("%s : TraceMatch(%s) = false", c.cidr, ip)
			}
		}
		for _, ip := range c.out {
			if TraceMatch(p, ip) {
				t.Errorf("%s : TraceMatch(%s) = true", c.cidr, ip)
			}
		}
	}
	if _, _, ok := TraceIPRange(netip.MustParsePrefix("0.0.0.0/0")); ok {
		t.Error("0.0.0.0/0 ne doit pas restreindre la requête")
	}
}

func TestParseTraceTarget(t *testing.T) {
	for in, want := range map[string]string{
		"203.0.113.9":      "203.0.113.9/32",
		"203.0.113.9/24":   "203.0.113.0/24",
		"::ffff:192.0.2.1": "192.0.2.1/32",
		" 2001:db8::1 ":    "2001:db8::1/128",
	} {
		p, err := ParseTraceTarget(in)
		if err != nil || p.String() != want {
			t.Errorf("%q : %v, %v (attendu %s)", in, p, err, want)
		}
	}
	if _, err := ParseTraceTarget("pas une ip"); err == nil {
		t.Error("une entrée invalide doit être refusée")
	}
}

func TestTraceOverlap(t *testing.T) {
	p, _ := ParseTraceTarget("203.0.113.0/24")
	for v, want := range map[string]bool{
		"203.0.113.9": true, "203.0.0.0/16": true, "203.0.113.128/25": true,
		"203.0.114.1": false, "not-an-ip": false,
	} {
		if TraceOverlap(p, v) != want {
			t.Errorf("TraceOverlap(%s) = %v", v, !want)
		}
	}
}

func TestBurstBuilderSplitsOnQuietGaps(t *testing.T) {
	t0 := time.Date(2026, 1, 1, 10, 0, 0, 0, time.UTC)
	var bb BurstBuilder
	for i, r := range []TraceRequest{
		{Ts: t0, IP: "203.0.113.1", Domain: "a.test", Method: "GET", Path: "/wp-login.php", Status: 404},
		{Ts: t0.Add(time.Minute), IP: "203.0.113.2", Domain: "a.test", Method: "GET", Path: "/wp-login.php", Status: 403, WAFMatches: []string{"sqli"}},
		{Ts: t0.Add(3 * time.Hour), IP: "203.0.113.1", Domain: "b.test", Method: "POST", Path: "/", Status: 200},
	} {
		_ = i
		bb.Add(r)
	}
	bb.Done()
	if len(bb.Bursts) != 2 {
		t.Fatalf("%d épisodes, attendu 2", len(bb.Bursts))
	}
	b := bb.Bursts[0]
	if b.Requests != 2 || b.Blocked != 1 || b.IPCount != 2 || b.Statuses["4xx"] != 2 {
		t.Errorf("épisode 1 : %+v", b)
	}
	if len(b.TopPaths) != 1 || b.TopPaths[0].Count != 2 || b.WAFMatches[0].Value != "sqli" {
		t.Errorf("épisode 1 chemins/WAF : %+v %+v", b.TopPaths, b.WAFMatches)
	}
	if !b.End.Equal(t0.Add(time.Minute)) || bb.Bursts[1].Domains[0] != "b.test" {
		t.Errorf("bornes ou domaines : %+v / %+v", b, bb.Bursts[1])
	}
}
