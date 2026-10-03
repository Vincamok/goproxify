// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package security

import (
	"errors"
	"strings"
	"testing"
)

func TestParseBanTargetNormalizes(t *testing.T) {
	cases := []struct {
		in, want, kind string
	}{
		{"203.0.113.9", "203.0.113.9", "ip"},
		{" 203.0.113.9 ", "203.0.113.9", "ip"},
		{"203.0.113.9/32", "203.0.113.9", "ip"},
		{"203.0.113.7/24", "203.0.113.0/24", "cidr"}, // adresse d'hôte ramenée au réseau
		{"203.0.113.0/24", "203.0.113.0/24", "cidr"},
		{"2001:DB8::1", "2001:db8::1", "ip"},
		{"2001:db8:abcd:12::/64", "2001:db8:abcd:12::/64", "cidr"},
		{"2001:db8:abcd:12:ffff::1/64", "2001:db8:abcd:12::/64", "cidr"},
		{"::ffff:203.0.113.9", "203.0.113.9", "ip"}, // IPv4 mappée
		{"198.51.0.0/16", "198.51.0.0/16", "cidr"},
	}
	for _, tc := range cases {
		got, err := ParseBanTarget(tc.in)
		if err != nil {
			t.Errorf("%q : %v", tc.in, err)
			continue
		}
		if got.Value != tc.want || got.Kind() != tc.kind {
			t.Errorf("%q → %q (%s), attendu %q (%s)", tc.in, got.Value, got.Kind(), tc.want, tc.kind)
		}
	}
}

func TestParseBanTargetRejects(t *testing.T) {
	cases := map[string]string{
		"":                 "requis",
		"   ":              "requis",
		"not-an-ip":        "invalide",
		"203.0.113.256":    "invalide",
		"203.0.113.0/33":   "invalide",
		"203.0.113.0/":     "invalide",
		"fe80::1%eth0":     "zone",
		"10.0.0.0/8":       "trop large",
		"0.0.0.0/0":        "trop large",
		"198.51.0.0/15":    "trop large",
		"::/0":             "trop large",
		"2001:db8::/31":    "trop large",
		"203.0.113.1-9":    "invalide",
		"203.0.113.1, 2.3": "invalide",
	}
	for in, want := range cases {
		_, err := ParseBanTarget(in)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q : erreur %v, attendu un message contenant %q", in, err, want)
		}
	}
	if _, err := ParseBanTarget(""); !errors.Is(err, ErrBanTargetEmpty) {
		t.Errorf("cible vide : %v", err)
	}
}

func TestBanTargetAddresses(t *testing.T) {
	for in, want := range map[string]float64{"203.0.113.9": 1, "203.0.113.0/24": 256, "198.51.0.0/16": 65536, "2001:db8::/64": 1 << 63 * 2} {
		got, _ := ParseBanTarget(in)
		if got.Addresses() != want {
			t.Errorf("%s : %v adresses, attendu %v", in, got.Addresses(), want)
		}
	}
}

// Une plage qui contient l'adresse du demandeur le couperait ; une adresse seule reste permise.
func TestCheckBanLockout(t *testing.T) {
	rng, _ := ParseBanTarget("203.0.113.0/24")
	var lock ErrBanLockout
	if err := CheckBanLockout(rng, "203.0.113.77"); !errors.As(err, &lock) || lock.Requester != "203.0.113.77" {
		t.Fatalf("plage contenant le demandeur : %v", err)
	}
	if err := CheckBanLockout(rng, "198.51.100.1"); err != nil {
		t.Fatalf("plage sans le demandeur : %v", err)
	}
	if err := CheckBanLockout(rng, "pas-une-ip"); err != nil {
		t.Fatalf("adresse du demandeur illisible : %v", err)
	}
	single, _ := ParseBanTarget("203.0.113.77")
	if err := CheckBanLockout(single, "203.0.113.77"); err != nil {
		t.Fatalf("adresse seule : comportement historique conservé, %v", err)
	}
	v6, _ := ParseBanTarget("2001:db8:1:1::/64")
	if err := CheckBanLockout(v6, "2001:db8:1:1::abcd"); err == nil {
		t.Fatal("IPv6 : le demandeur est dans la plage")
	}
}

func TestBanTargetPrivateRange(t *testing.T) {
	for in, want := range map[string]bool{
		"192.168.1.0/24": true, "10.1.0.0/16": true, "127.0.0.1": true, "169.254.1.1": true,
		"203.0.113.0/24": false, "8.8.8.8": false,
	} {
		got, _ := ParseBanTarget(in)
		if got.PrivateRange() != want {
			t.Errorf("%s : PrivateRange=%v, attendu %v", in, got.PrivateRange(), want)
		}
	}
}
