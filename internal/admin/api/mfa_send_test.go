// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/mfa"
)

func TestSendLimiter_PerUserAndGlobal(t *testing.T) {
	l := newMFALimiter()
	for i := 0; i < sendMaxPerUser; i++ {
		if ok, _ := l.allowSend("u1"); !ok {
			t.Fatalf("envoi %d refusé trop tôt", i)
		}
	}
	if ok, wait := l.allowSend("u1"); ok || wait <= 0 {
		t.Fatalf("le quatrième envoi doit être refusé avec un délai, ok=%v wait=%v", ok, wait)
	}
	if ok, _ := l.allowSend("u2"); !ok {
		t.Fatal("un autre compte ne doit pas être touché")
	}

	g := newMFALimiter()
	sent := 0
	for i := 0; i < 200; i++ {
		if ok, _ := g.allowSend(string(rune('a' + i%26)) + string(rune('A'+i/26))); ok {
			sent++
		}
	}
	if sent != sendMaxGlobal {
		t.Fatalf("plafond global : %d envoyés, attendu %d", sent, sendMaxGlobal)
	}
}

func TestSMSSetup_RejectsNonE164AndThrottles(t *testing.T) {
	h, _, userID := newMFAForLimit(t)
	post := func(phone string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/sms/setup", strings.NewReader(`{"phone":"`+phone+`"}`))
		rr := httptest.NewRecorder()
		h.smsSetup(rr, req, userID)
		return rr.Code
	}
	for _, bad := range []string{"0612345678", "+33 6 12 34 56 78", "+0123456789", "1900premium", "+1234567"} {
		if c := post(bad); c != http.StatusBadRequest {
			t.Fatalf("%q : %d, attendu 400", bad, c)
		}
	}
}

func TestPushConfig_RefusesMetadataAndBadTopic(t *testing.T) {
	cases := []struct {
		name string
		cfg  mfa.PushConfig
		ok   bool
	}{
		{"ntfy.sh par défaut", mfa.PushConfig{Provider: "ntfy", Topic: "alertes"}, true},
		{"ntfy privé auto-hébergé", mfa.PushConfig{Provider: "ntfy", Topic: "alertes", URL: "http://10.0.0.5:8080"}, true},
		{"métadonnées du cloud", mfa.PushConfig{Provider: "gotify", URL: "http://169.254.169.254/latest"}, false},
		{"schéma file", mfa.PushConfig{Provider: "gotify", URL: "file:///etc/passwd"}, false},
		{"topic avec chemin", mfa.PushConfig{Provider: "ntfy", Topic: "../admin", URL: "http://10.0.0.5"}, false},
		{"topic vide", mfa.PushConfig{Provider: "ntfy"}, false},
		{"gotify sans url", mfa.PushConfig{Provider: "gotify"}, false},
		{"provider inconnu", mfa.PushConfig{Provider: "x"}, false},
	}
	for _, c := range cases {
		if err := c.cfg.Validate(); (err == nil) != c.ok {
			t.Errorf("%s : err=%v, attendu ok=%v", c.name, err, c.ok)
		}
	}
}
