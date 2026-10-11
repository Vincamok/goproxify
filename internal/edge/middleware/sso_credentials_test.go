// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"golang.org/x/crypto/bcrypt"
)

func basicReq(remote, user, pass, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodGet, "http://app.example.fr/secret", nil)
	r.RemoteAddr = remote
	r.SetBasicAuth(user, pass)
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// Cinq mots de passe faux depuis une adresse verrouillent le couple adresse + identifiant (429, même pour le bon mot
// de passe) ; changer d'en-tête n'y change rien ; une autre adresse et un autre identifiant ne sont pas touchés.
func TestBasicAuth_PasswordGuessingIsLimited(t *testing.T) {
	basicLimiter = NewAuthFailLimiter()
	h := SSOAuth(fullSSO("basic"))(ssoBackend())
	do := func(remote, user, pass, xff string) int {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, basicReq(remote, user, pass, xff))
		return rec.Code
	}
	for i := 0; i < authFailPerClient; i++ {
		if code := do("203.0.113.7:4000", "u", "faux", "10.0.0."+string(rune('1'+i))); code != http.StatusUnauthorized {
			t.Fatalf("essai %d : %d (attendu 401)", i+1, code)
		}
	}
	if code := do("203.0.113.7:4000", "u", "p", "10.9.9.9"); code != http.StatusTooManyRequests {
		t.Fatalf("le bon mot de passe depuis l'adresse verrouillée : %d (attendu 429)", code)
	}
	if code := do("198.51.100.20:4000", "u", "p", ""); code != http.StatusOK {
		t.Fatalf("une autre adresse doit pouvoir s'authentifier : %d", code)
	}
	if code := do("203.0.113.7:4000", "autre", "x", ""); code != http.StatusUnauthorized {
		t.Fatalf("un autre identifiant depuis la même adresse n'est pas verrouillé : %d", code)
	}
}

func TestAuthFailLimiter_PerUserAcrossAddressesAndBounded(t *testing.T) {
	l := NewAuthFailLimiter()
	for i := 0; i < authFailPerUser; i++ {
		l.fail(userOnlyKey("Alice"), authFailPerUser)
	}
	if blocked, wait := l.blocked(clientKey("1.2.3.4", "alice"), userOnlyKey("alice")); !blocked || wait <= 0 {
		t.Fatal("20 échecs, toutes adresses confondues, verrouillent l'identifiant")
	}
	l.success(userOnlyKey("alice"))
	if blocked, _ := l.blocked(userOnlyKey("alice")); blocked {
		t.Error("un succès lève le verrou")
	}
	// Fenêtre échue : le compteur repart de zéro, et la table est purgée.
	b := NewAuthFailLimiter()
	for i := 0; i < authMaxKeys+100; i++ {
		b.fail("k"+strings.Repeat("x", i%7)+string(rune(i)), 5)
	}
	b.mu.Lock()
	for _, bk := range b.m {
		bk.windowStart = bk.windowStart.Add(-2 * authFailWindow)
	}
	b.mu.Unlock()
	b.fail("derniere", 5)
	b.mu.Lock()
	n := len(b.m)
	b.mu.Unlock()
	if n > 10 {
		t.Errorf("%d entrées après purge", n)
	}
}

// Un identifiant inconnu coûte autant de temps qu'un mot de passe faux (bcrypt dans les deux cas).
func TestBasicAuth_UnknownUserCostsAsMuchAsWrongPassword(t *testing.T) {
	cfg := fullSSO("basic")
	hash := mustBcrypt(t, "p")
	cfg.BasicUsers[0].Password = hash
	basicLimiter = NewAuthFailLimiter()
	h := SSOAuth(cfg)(ssoBackend())
	timeOf := func(user string) time.Duration {
		var best time.Duration
		for i := 0; i < 3; i++ {
			start := time.Now()
			h.ServeHTTP(httptest.NewRecorder(), basicReq("198.51.100."+string(rune('1'+i))+":1", user, "faux", ""))
			if d := time.Since(start); best == 0 || d < best {
				best = d
			}
		}
		return best
	}
	known, unknown := timeOf("u"), timeOf("personne")
	if unknown < known/3 {
		t.Errorf("identifiant inconnu %v contre mot de passe faux %v : la durée révèle les comptes existants", unknown, known)
	}
}

func TestBuildLDAPFilter(t *testing.T) {
	for _, tc := range []struct{ filter, user, want string }{
		{"(uid=%s)", "alice", "(uid=alice)"},
		{"(|(sAMAccountName=%s)(uid=%s))", "alice", "(|(sAMAccountName=alice)(uid=alice))"},
		{"(uid=%s)", "*)(uid=*", `(uid=\2a\29\28uid=\2a)`},
		{"(uid=%s)", `a\b`, `(uid=a\5cb)`},
	} {
		if got := buildLDAPFilter(tc.filter, tc.user); got != tc.want {
			t.Errorf("%q avec %q : %q, attendu %q", tc.filter, tc.user, got, tc.want)
		}
	}
}

func mustBcrypt(t *testing.T, password string) string {
	t.Helper()
	h, err := bcrypt.GenerateFromPassword([]byte(password), bcrypt.DefaultCost)
	if err != nil {
		t.Fatal(err)
	}
	return string(h)
}
