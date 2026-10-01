// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package fail2ban

import (
	"net/http"
	"testing"
)

func newTestEngine(whitelist ...string) (*Engine, *[]Ban) {
	e := New()
	e.UpdateConfig(Config{Enabled: true, WindowSec: 300, MaxErrors: 3, Whitelist: whitelist})
	var bans []Ban
	e.OnBan = func(b Ban) { bans = append(bans, b) }
	return e, &bans
}

func banIPs(bans []Ban) []string {
	out := make([]string, 0, len(bans))
	for _, b := range bans {
		out = append(out, b.IP)
	}
	return out
}

func TestFeedBanTarget(t *testing.T) {
	for _, tc := range []struct{ fed, want string }{
		{"203.0.113.7", "203.0.113.7"},
		{"203.0.113.8:51234", "203.0.113.8"},
		{"2a01:e0a:1:2::5", "2a01:e0a:1:2::/64"},
		{"[2a01:e0a:1:3::5]:443", "2a01:e0a:1:3::/64"},
		{"::ffff:203.0.113.9", "203.0.113.9"},
	} {
		e, bans := newTestEngine()
		for i := 0; i < 3; i++ {
			e.Feed(tc.fed, http.StatusForbidden)
		}
		if got := banIPs(*bans); len(got) != 1 || got[0] != tc.want {
			t.Errorf("Feed(%q) : bans %v, attendu [%s]", tc.fed, got, tc.want)
		}
	}
}

func TestFeedIgnoresNonPublicOrInvalidIPs(t *testing.T) {
	for _, ip := range []string{"", "[pseudonymisé]", "10.0.0.5", "fd00::5", "[::1]:8080", "2606:4700::1"} {
		e, bans := newTestEngine()
		for i := 0; i < 3; i++ {
			e.Feed(ip, http.StatusForbidden)
		}
		if len(*bans) != 0 {
			t.Errorf("Feed(%q) ne doit pas bannir : %v", ip, banIPs(*bans))
		}
	}
}

func TestFeedAggregatesIPv6By64(t *testing.T) {
	e, bans := newTestEngine()
	for _, ip := range []string{"2a01:e0a:1:2::5", "2a01:e0a:1:2::6", "2a01:e0a:1:2:abcd::7"} {
		e.Feed(ip, http.StatusForbidden)
	}
	if got := banIPs(*bans); len(got) != 1 || got[0] != "2a01:e0a:1:2::/64" {
		t.Fatalf("3 adresses d'un même /64 : bans %v, attendu [2a01:e0a:1:2::/64]", got)
	}
}

func TestFeedIPv6Whitelist(t *testing.T) {
	e, bans := newTestEngine("2a01:e0a:1:4::5")
	for i := 0; i < 5; i++ {
		e.Feed("2a01:e0a:1:4::5", http.StatusForbidden)
	}
	if len(*bans) != 0 {
		t.Fatalf("une IPv6 en liste blanche ne doit pas être bannie : %v", banIPs(*bans))
	}
	for i := 0; i < 3; i++ {
		e.Feed("2a01:e0a:1:4::6", http.StatusForbidden)
	}
	if got := banIPs(*bans); len(got) != 1 || got[0] != "2a01:e0a:1:4::6" {
		t.Fatalf("voisine d'une IP exemptée : bans %v, attendu l'adresse seule, pas le /64", got)
	}
	if !e.Whitelisted("2a01:e0a:1:4::/64") {
		t.Error("un ban /64 contenant une IP exemptée doit être considéré en liste blanche")
	}
	if e.Whitelisted("2a01:e0a:1:5::/64") {
		t.Error("un /64 sans IP exemptée n'est pas en liste blanche")
	}
}

func TestFeedIPv6WhitelistCIDR(t *testing.T) {
	e, bans := newTestEngine("2a01:e0a:1::/48")
	for i := 0; i < 5; i++ {
		e.Feed("[2a01:e0a:1:7::9]:443", http.StatusForbidden)
	}
	if len(*bans) != 0 {
		t.Fatalf("une IPv6 couverte par un CIDR en liste blanche ne doit pas être bannie : %v", banIPs(*bans))
	}
}

func TestUnbanIPResetsIPv6Counter(t *testing.T) {
	e, bans := newTestEngine()
	for i := 0; i < 3; i++ {
		e.Feed("2a01:e0a:1:2::5", http.StatusForbidden)
	}
	e.UnbanIP("2a01:e0a:1:2::/64")
	for i := 0; i < 2; i++ {
		e.Feed("2a01:e0a:1:2::5", http.StatusForbidden)
	}
	if len(*bans) != 1 {
		t.Fatalf("après déban, le compteur repart de zéro : %v", banIPs(*bans))
	}
	e.Feed("2a01:e0a:1:2::5", http.StatusForbidden)
	if len(*bans) != 2 {
		t.Fatalf("après déban, le /64 peut de nouveau être banni : %v", banIPs(*bans))
	}
}
