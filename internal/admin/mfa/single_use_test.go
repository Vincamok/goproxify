// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"context"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"

	"golang.org/x/crypto/bcrypt"

	"github.com/vincamok/goproxify/internal/admin/db"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	d, err := db.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { d.Close() })
	return NewStore(d)
}

// race lance n goroutines qui tentent la même opération et retourne combien ont réussi.
func race(n int, op func() bool) int {
	var ok atomic.Int32
	var wg sync.WaitGroup
	start := make(chan struct{})
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			<-start
			if op() {
				ok.Add(1)
			}
		}()
	}
	close(start)
	wg.Wait()
	return int(ok.Load())
}

// Un défi WebAuthn appartient à l'utilisateur qui l'a demandé, ne sert qu'une fois, même présenté en même temps.
func TestWebAuthnChallenge_BoundToUserAndSingleUse(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	id, err := s.CreateWebAuthnChallenge(ctx, "alice", map[string]string{"challenge": "c"})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err := s.GetWebAuthnChallenge(ctx, "mallory", id, &data); err == nil {
		t.Fatal("le défi d'un autre utilisateur ne doit pas être utilisable")
	}
	if got := race(8, func() bool {
		var d map[string]string
		return s.GetWebAuthnChallenge(ctx, "alice", id, &d) == nil
	}); got != 1 {
		t.Fatalf("%d lectures du même défi ont réussi, attendu exactement 1", got)
	}
	if err := s.GetWebAuthnChallenge(ctx, "alice", id, &data); err == nil {
		t.Error("un défi consommé ne se relit pas")
	}
}

// Un défi de connexion par code (courriel, SMS) ne peut pas servir de défi WebAuthn.
func TestWebAuthnChallenge_OnlyWebAuthnMethod(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	id, err := s.CreateChallenge(ctx, "alice", MethodEmail, "123456", map[string]string{"x": "y"})
	if err != nil {
		t.Fatal(err)
	}
	var data map[string]string
	if err := s.GetWebAuthnChallenge(ctx, "alice", id, &data); err == nil {
		t.Error("un défi courriel ne doit pas être lu comme défi WebAuthn")
	}
}

func TestOTPChallenge_SingleUseUnderConcurrency(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	if _, err := s.CreateChallenge(ctx, "alice", MethodEmail, "654321", nil); err != nil {
		t.Fatal(err)
	}
	if got := race(8, func() bool { _, ok := s.VerifyChallenge(ctx, "alice", MethodEmail, "654321"); return ok }); got != 1 {
		t.Fatalf("%d validations du même code ont réussi, attendu exactement 1", got)
	}
}

func TestBackupCode_SingleUseUnderConcurrency(t *testing.T) {
	s, ctx := newTestStore(t), context.Background()
	plain, hashes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatal(err)
	}
	if err := s.SaveBackupCodes(ctx, "alice", hashes); err != nil {
		t.Fatal(err)
	}
	if got := race(8, func() bool { return s.VerifyBackupCode(ctx, "alice", plain[0]) }); got != 1 {
		t.Fatalf("%d utilisations du même code de secours ont réussi, attendu exactement 1", got)
	}
	if s.VerifyBackupCode(ctx, "alice", plain[0]) {
		t.Error("un code de secours utilisé ne revalide pas")
	}
	if !s.VerifyBackupCode(ctx, "alice", plain[1]) {
		t.Error("les autres codes restent valables")
	}
}

// Un code de secours généré se valide : il était haché en majuscules et comparé en minuscules, aucun ne passait.
func TestBackupCode_GeneratedCodesVerifyInAnyFormat(t *testing.T) {
	plain, hashes, err := GenerateBackupCodes()
	if err != nil {
		t.Fatal(err)
	}
	for _, form := range []string{plain[0], strings.ToLower(plain[0]), strings.ReplaceAll(plain[0], "-", ""), strings.ReplaceAll(plain[0], "-", " ")} {
		if !CheckBackupCode(hashes[0], form) {
			t.Errorf("le code %q ne se valide pas", form)
		}
	}
	if CheckBackupCode(hashes[0], plain[1]) || CheckBackupCode(hashes[0], "0000-0000-0000") {
		t.Error("un autre code ne doit pas se valider")
	}
}

// Les codes déjà remis (haches calculés sur la forme en majuscules) fonctionnent aussi.
func TestBackupCode_LegacyUppercaseHashesStillWork(t *testing.T) {
	legacy, err := bcrypt.GenerateFromPassword([]byte("8B29B899A7C7"), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	if !CheckBackupCode(string(legacy), "8B29-B899-A7C7") || !CheckBackupCode(string(legacy), "8b29b899a7c7") {
		t.Error("un code généré avant la correction doit se valider")
	}
}
