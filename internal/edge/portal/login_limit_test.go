// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Le formulaire de connexion du portail ne se devine pas sans limite : cinq mots de passe faux verrouillent le
// couple adresse + identifiant (429, même pour le bon mot de passe) ; une autre adresse n'est pas touchée.
func TestPortalLogin_PasswordGuessingIsLimited(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{ID: "u1", Username: "a@b.c", PasswordHash: hash, Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)

	login := func(remote, user, pass string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(`{"username":"`+user+`","password":"`+pass+`"}`))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < 5; i++ {
		if code := login("203.0.113.7:4000", "a@b.c", "faux"); code != http.StatusUnauthorized {
			t.Fatalf("essai %d : %d (attendu 401)", i+1, code)
		}
	}
	if code := login("203.0.113.7:4000", "a@b.c", "password1"); code != http.StatusTooManyRequests {
		t.Fatalf("le bon mot de passe depuis l'adresse verrouillée : %d (attendu 429)", code)
	}
	if code := login("198.51.100.9:4000", "a@b.c", "password1"); code != http.StatusOK {
		t.Fatalf("une autre adresse doit pouvoir se connecter : %d", code)
	}
	// Un identifiant inconnu échoue pareillement (401) et compte aussi.
	if code := login("203.0.113.7:4000", "inconnu", "x"); code != http.StatusUnauthorized {
		t.Fatalf("identifiant inconnu : %d", code)
	}
}

// Un défi de second facteur se détruit au cinquième code faux : sans cela le code se devinait à volonté.
func TestPortal2FAChallenge_DestroyedAfterFiveWrongCodes(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "secret")
	hash, _ := HashPassword("password1")
	secret, err := TOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	_ = store.CreateUser(UserRecord{ID: "u1", Username: "a@b.c", PasswordHash: hash, Status: UserStatusActive,
		TOTPEnabled: true, TOTPSecret: secret, CreatedAt: time.Now().UTC().Format(time.RFC3339)})
	h := NewHTTPServer(&Config{Enabled: true}, store, NewSessionManager(), nil, nil)
	ch := newMFAChallenge("u1", "a@b.c", [32]byte{})
	h.challenges.Put(ch)

	verify := func(code string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/2fa/verify", strings.NewReader(`{"challenge_id":"`+ch.ID+`","method":"totp","code":"`+code+`"}`))
		rec := httptest.NewRecorder()
		h.Handler().ServeHTTP(rec, req)
		return rec.Code
	}
	for i := 0; i < MaxChallengeFailures-1; i++ {
		if code := verify("000000"); code != http.StatusUnauthorized {
			t.Fatalf("code faux %d : %d (attendu 401)", i+1, code)
		}
	}
	if code := verify("000001"); code != http.StatusGone {
		t.Fatalf("au cinquième code faux le défi est détruit : %d (attendu 410)", code)
	}
	good, _ := TOTPCode(secret)
	if code := verify(good); code != http.StatusGone {
		t.Fatalf("le bon code ne sert plus sur un défi détruit : %d (attendu 410)", code)
	}
}
