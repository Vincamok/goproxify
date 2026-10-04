// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package threat

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/edge/tlsfp"
)

func withFP(fp *tlsfp.Fingerprint) *http.Request {
	r := httptest.NewRequest("GET", "/", nil)
	return r.WithContext(tlsfp.WithContext(r.Context(), fp))
}

func TestCheckTLSFingerprint(t *testing.T) {
	var banned []string
	e := New(slog.Default(), func(ip, reason string, _ time.Time) { banned = append(banned, ip+" "+reason) })
	e.UpdateConfig(Config{
		Enabled: true,
		Mode:    "block",
		CustomLists: CustomListsConfig{
			TLSFingerprints: []string{" E7D705A3286E19EA42F587B344EE6865 ", "t13d1516h2_8daaf6152771_02713d6af862"},
		},
	})

	scanner := &tlsfp.Fingerprint{JA3Hash: "e7d705a3286e19ea42f587b344ee6865", JA4: "t13d0000h2_x_y"}
	blocked, reason := e.Check(withFP(scanner), "9.9.9.9")
	if !blocked || reason != "threat: tls_fp" {
		t.Fatalf("JA3 listé : blocked=%v reason=%q", blocked, reason)
	}
	if len(banned) != 1 || banned[0] != "9.9.9.9 threat: tls_fp" {
		t.Fatalf("ban attendu, obtenu %v", banned)
	}

	byJA4 := &tlsfp.Fingerprint{JA3Hash: "0000", JA4: "t13d1516h2_8daaf6152771_02713d6af862"}
	if blocked, _ := e.Check(withFP(byJA4), "9.9.9.8"); !blocked {
		t.Fatal("JA4 listé non bloqué")
	}

	browser := &tlsfp.Fingerprint{JA3Hash: "1111", JA4: "t13d1517h2_aaaaaaaaaaaa_bbbbbbbbbbbb"}
	if blocked, _ := e.Check(withFP(browser), "9.9.9.7"); blocked {
		t.Fatal("empreinte inconnue bloquée")
	}
	if blocked, _ := e.Check(httptest.NewRequest("GET", "/", nil), "9.9.9.6"); blocked {
		t.Fatal("requête sans TLS (HTTP clair) ne doit pas correspondre")
	}
}

func TestCheckTLSFingerprintDetectModeDoesNotBan(t *testing.T) {
	banned := 0
	e := New(slog.Default(), func(string, string, time.Time) { banned++ })
	e.UpdateConfig(Config{Enabled: true, Mode: "detect", CustomLists: CustomListsConfig{TLSFingerprints: []string{"abc"}}})
	blocked, reason := e.Check(withFP(&tlsfp.Fingerprint{JA3Hash: "abc"}), "1.1.1.1")
	if blocked || reason != "threat: tls_fp" || banned != 0 {
		t.Fatalf("detect : blocked=%v reason=%q bans=%d", blocked, reason, banned)
	}
}

func TestCheckTLSFingerprintWhitelistedIPExempt(t *testing.T) {
	e := New(slog.Default(), nil)
	e.UpdateConfig(Config{Enabled: true, CustomLists: CustomListsConfig{TLSFingerprints: []string{"abc"}}, Whitelist: Whitelist{IPs: []string{"10.0.0.5"}}})
	if blocked, _ := e.Check(withFP(&tlsfp.Fingerprint{JA3Hash: "abc"}), "10.0.0.5"); blocked {
		t.Fatal("IP en liste blanche bloquée par empreinte")
	}
}
