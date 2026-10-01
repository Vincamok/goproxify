// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package router_test

import (
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/router"
)

func TestBanStoreCheckBlocked(t *testing.T) {
	store := router.NewBanStore()
	exp := time.Now().Add(time.Hour)
	store.Replace([]*router.RuntimeBan{
		{ID: "1", IP: "203.0.113.10", Reason: "probe", Source: "crowdsec"},
		{ID: "2", IP: "198.51.100.0/24", Reason: "range", Source: "crowdsec", ExpiresAt: &exp},
		{ID: "3", IP: "192.0.2.1", Reason: "expired", Source: "native", ExpiresAt: ptrTime(time.Now().Add(-time.Minute))},
	})

	if store.Len() != 2 {
		t.Fatalf("Len=%d want 2 (expired filtered)", store.Len())
	}

	if blocked, _ := store.CheckBlocked("203.0.113.10"); !blocked {
		t.Fatal("exact IP should be blocked")
	}
	if blocked, reason := store.CheckBlocked("198.51.100.50"); !blocked || reason == "" {
		t.Fatalf("CIDR member should be blocked, reason=%q", reason)
	}
	if blocked, _ := store.CheckBlocked("192.0.2.1"); blocked {
		t.Fatal("expired ban should not block")
	}
	if blocked, _ := store.CheckBlocked("10.0.0.5"); blocked {
		t.Fatal("private IP must never be blocked")
	}
	if blocked, _ := store.CheckBlocked("8.8.8.8"); blocked {
		t.Fatal("unrelated IP must pass")
	}
}

// Fail2Ban bannit un /64 pour une IPv6 (ou l'adresse seule si la liste blanche recoupe le /64).
func TestBanStoreCheckBlockedIPv6(t *testing.T) {
	store := router.NewBanStore()
	store.Replace([]*router.RuntimeBan{
		{ID: "1", IP: "2a01:e0a:1:2::/64", Source: "fail2ban"},
		{ID: "2", IP: "2a01:e0a:1:4::6", Source: "fail2ban"},
	})
	for ip, want := range map[string]bool{
		"2a01:e0a:1:2::5":               true,
		"2a01:e0a:1:2:ffff:ffff:ffff:1": true,
		"2a01:e0a:1:3::5":               false,
		"2a01:e0a:1:4::6":               true,
		"2a01:e0a:1:4::5":               false,
	} {
		if blocked, _ := store.CheckBlocked(ip); blocked != want {
			t.Errorf("CheckBlocked(%s) = %v, want %v", ip, blocked, want)
		}
	}
}

func TestIPProfileAllowBypassesLogic(t *testing.T) {
	profiles := router.NewIPProfileStore()
	profiles.Replace([]*router.IPProfile{
		{ID: "allow", Name: "office", Mode: "allow", CIDRs: []string{"203.0.113.0/24"}},
	})
	if !profiles.IsAllowed("203.0.113.99") {
		t.Fatal("allow profile should match")
	}
	if profiles.IsAllowed("198.51.100.1") {
		t.Fatal("non-allow IP should not be IsAllowed")
	}
	if !profiles.IsAllowed("10.1.2.3") {
		t.Fatal("private IP should be IsAllowed")
	}
}

func ptrTime(t time.Time) *time.Time { return &t }
