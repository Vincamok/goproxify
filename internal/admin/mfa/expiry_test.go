// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func TestChallengesAndDevicesExpireInUTC(t *testing.T) {
	// Processus à UTC-5 : l'échéance à l'heure locale, comparée en texte à CURRENT_TIMESTAMP (UTC),
	// était déjà dépassée (et, à UTC+2 comme Europe/Paris, un code OTP restait valable 2 h 05).
	prev := time.Local
	time.Local = time.FixedZone("EST", -5*3600)
	t.Cleanup(func() { time.Local = prev })
	d, err := db.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	s, ctx := NewStore(d), context.Background()

	if _, err := s.CreateChallenge(ctx, "u1", MethodEmail, "123456", nil); err != nil {
		t.Fatal(err)
	}
	if _, ok := s.VerifyChallenge(ctx, "u1", MethodEmail, "123456"); !ok {
		t.Error("un code OTP valable 5 min doit être accepté aussitôt")
	}
	id, err := s.CreateWebAuthnChallenge(ctx, "u1", map[string]string{"challenge": "c"})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err := s.GetWebAuthnChallenge(ctx, id, &data); err != nil {
		t.Errorf("challenge WebAuthn valable 5 min : %v", err)
	}
	if _, err := s.CreateTrustedDevice(ctx, "u1", "hash", "portable"); err != nil {
		t.Fatal(err)
	}
	if !s.IsTrustedDevice(ctx, "u1", "hash") {
		t.Error("l'appareil de confiance vient d'être enregistré")
	}
	var n int
	d.QueryRow(`SELECT COUNT(*) FROM user_mfa_challenges WHERE expires_at > datetime('now', '+6 minutes')`).Scan(&n) //nolint:errcheck
	if n != 0 {
		t.Errorf("%d challenge valable plus de 5 min", n)
	}
}
