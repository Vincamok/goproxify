// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func reqFrom(remote, xff string) *http.Request {
	r := httptest.NewRequest(http.MethodPost, "/", nil)
	r.RemoteAddr = remote
	if xff != "" {
		r.Header.Set("X-Forwarded-For", xff)
	}
	return r
}

// L'en-tête X-Forwarded-For ne sert de clé que derrière un proxy (connexion venue d'une adresse privée), et on
// retient la dernière entrée — celle du proxy — pas la première, que le client choisit.
func TestLimiterIP_DoesNotTrustClientChosenHeaders(t *testing.T) {
	for _, tc := range []struct{ name, remote, xff, want string }{
		{"connexion directe d'Internet : en-tête ignoré", "203.0.113.7:5555", "1.2.3.4", "203.0.113.7"},
		{"directe, plusieurs entrées : ignoré", "203.0.113.7:5555", "1.1.1.1, 2.2.2.2", "203.0.113.7"},
		{"derrière un proxy privé : dernière entrée", "10.0.0.2:4000", "9.9.9.9, 198.51.100.4", "198.51.100.4"},
		{"derrière un proxy local : dernière entrée", "127.0.0.1:4000", "198.51.100.4", "198.51.100.4"},
		{"proxy privé, en-tête illisible : adresse du proxy", "10.0.0.2:4000", "pas-une-ip", "10.0.0.2"},
		{"proxy privé, sans en-tête", "10.0.0.2:4000", "", "10.0.0.2"},
	} {
		if got := limiterIP(reqFrom(tc.remote, tc.xff)); got != tc.want {
			t.Errorf("%s : %q, attendu %q", tc.name, got, tc.want)
		}
	}
}

// Changer d'adresse (ou d'en-tête) à chaque requête ne remet pas le compteur d'un compte à zéro.
func TestLoginLimiter_AccountLockSurvivesChangingAddresses(t *testing.T) {
	l := newLoginLimiter()
	account := accountKey(" Victime@Exemple.fr ")
	for i := 0; i < loginMaxFailsPerAccount; i++ {
		ipKey := loginKey(fmt.Sprintf("203.0.113.%d", i+1), "victime@exemple.fr") // une adresse neuve à chaque essai
		if blocked, _ := l.blocked(ipKey, account); blocked && i < loginMaxFailsPerAccount-1 {
			t.Fatalf("verrouillé trop tôt (essai %d)", i+1)
		}
		l.fail(ipKey)
		l.failN(account, loginMaxFailsPerAccount)
	}
	if blocked, wait := l.blocked(loginKey("198.51.100.99", "victime@exemple.fr"), account); !blocked || wait <= 0 {
		t.Fatal("le compte doit être verrouillé même depuis une adresse jamais vue")
	}
	if accountKey("VICTIME@exemple.fr") != account {
		t.Error("la clé de compte ignore la casse et les espaces")
	}
	l.success(loginKey("198.51.100.99", "victime@exemple.fr"), account)
	if blocked, _ := l.blocked(account); blocked {
		t.Error("un succès lève le verrou du compte")
	}
}

func TestLoginLimiter_TableIsBounded(t *testing.T) {
	l := newLoginLimiter()
	for i := 0; i < maxLimiterKeys+500; i++ {
		l.fail(fmt.Sprintf("k%d", i))
	}
	// Les entrées dont la fenêtre est échue sont purgées ; ici toutes sont récentes, la purge ne retire rien, mais
	// la table ne s'agrandit pas sans fin une fois les fenêtres échues.
	l.mu.Lock()
	for _, b := range l.byKey {
		b.windowAt = b.windowAt.Add(-2 * loginWindowSecs)
	}
	l.mu.Unlock()
	l.fail("derniere")
	l.mu.Lock()
	n := len(l.byKey)
	l.mu.Unlock()
	if n > 10 {
		t.Errorf("%d entrées après purge, attendu ≤ 10", n)
	}
}

// Le secret d'appairage ne se devine pas sans limite : 20 secrets faux depuis une adresse la verrouillent, et le
// bon secret est alors refusé aussi ; une autre adresse n'est pas touchée.
func TestPairing_SecretBruteForceIsLockedOut(t *testing.T) {
	t.Setenv("GPX_PAIRING_SECRET", "le-bon-secret")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Server{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil)), loginLimit: newLoginLimiter()}

	pair := func(remote, xff, secret string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair", strings.NewReader(`{"secret":"`+secret+`","node_name":"edge-x","role":"edge"}`))
		req.RemoteAddr = remote
		if xff != "" {
			req.Header.Set("X-Forwarded-For", xff)
		}
		s.handlePair(rec, req)
		return rec.Code
	}
	for i := 0; i < pairMaxFails; i++ {
		// L'attaquant change son en-tête à chaque essai : sans effet, il vient d'une adresse publique.
		if code := pair("203.0.113.7:4000", fmt.Sprintf("10.9.8.%d", i), "faux"); code != http.StatusForbidden {
			t.Fatalf("essai %d : %d (attendu 403)", i+1, code)
		}
	}
	if code := pair("203.0.113.7:4000", "10.9.8.250", "le-bon-secret"); code != http.StatusTooManyRequests {
		t.Fatalf("le bon secret depuis l'adresse verrouillée : %d (attendu 429)", code)
	}
	if code := pair("198.51.100.20:4000", "", "le-bon-secret"); code != http.StatusOK {
		t.Fatalf("une autre adresse doit pouvoir s'appairer : %d", code)
	}
}
