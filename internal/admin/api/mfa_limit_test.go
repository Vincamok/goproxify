// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"github.com/go-webauthn/webauthn/webauthn"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mfa"
)

func newMFAForLimit(t *testing.T) (*MFAHandler, string, string) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "mfa.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &MFAHandler{DB: db, Store: mfa.NewStore(db), JWTSecret: "secret-limit"}
	totpSecret, err := mfa.TOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.UpsertMethod(context.Background(), "user-1", mfa.MethodTOTP, map[string]string{"secret": totpSecret}, true); err != nil {
		t.Fatal(err)
	}
	return h, totpSecret, "user-1"
}

func challenge(t *testing.T, h *MFAHandler, userID, method, code string) *httptest.ResponseRecorder {
	t.Helper()
	pending, err := adminauth.SignMFAPendingToken(userID, h.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	rec := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/challenge",
		strings.NewReader(`{"mfa_token":`+jsonQuote(pending)+`,"method":"`+method+`","code":"`+code+`"}`))
	h.ServeHTTP(rec, req)
	return rec
}

// Cinq codes faux verrouillent le second facteur du compte : même le bon code est ensuite refusé (429), et un
// nouveau jeton « mfa_pending » (nouveau mot de passe correct) n'y change rien.
func TestMFAChallenge_BruteForceIsLockedOut(t *testing.T) {
	h, secret, user := newMFAForLimit(t)
	for i := 0; i < mfaMaxFailsPerUser; i++ {
		if rec := challenge(t, h, user, "totp", "00000"+string(rune('0'+i))); rec.Code != http.StatusUnauthorized {
			t.Fatalf("tentative %d : %d (attendu 401)", i, rec.Code)
		}
	}
	good, _ := mfa.TOTPCode(secret)
	rec := challenge(t, h, user, "totp", good)
	if rec.Code != http.StatusTooManyRequests {
		t.Fatalf("après %d échecs, le bon code doit être refusé : %d", mfaMaxFailsPerUser, rec.Code)
	}
	if rec.Header().Get("Retry-After") == "" {
		t.Error("Retry-After attendu")
	}
	if rec := challenge(t, h, user, "backup", "ABCDEF123456"); rec.Code != http.StatusTooManyRequests {
		t.Errorf("les codes de secours sont verrouillés aussi : %d", rec.Code)
	}
	// Un autre compte n'est pas touché.
	if err := h.Store.UpsertMethod(context.Background(), "user-2", mfa.MethodTOTP, map[string]string{"secret": secret}, true); err != nil {
		t.Fatal(err)
	}
	if rec := challenge(t, h, "user-2", "totp", good); rec.Code != http.StatusOK {
		t.Errorf("un autre compte doit pouvoir se connecter : %d %s", rec.Code, rec.Body.String())
	}
}

func TestMFAChallenge_SuccessResetsCounterAndTOTPCannotBeReplayed(t *testing.T) {
	h, secret, user := newMFAForLimit(t)
	for i := 0; i < mfaMaxFailsPerUser-1; i++ {
		challenge(t, h, user, "totp", "111111")
	}
	good, _ := mfa.TOTPCode(secret)
	if rec := challenge(t, h, user, "totp", good); rec.Code != http.StatusOK {
		t.Fatalf("le bon code passe sous le seuil : %d %s", rec.Code, rec.Body.String())
	}
	// Rejeu : le même code, dans sa fenêtre, ne sert pas deux fois.
	if rec := challenge(t, h, user, "totp", good); rec.Code != http.StatusUnauthorized {
		t.Errorf("rejeu du même code TOTP : %d (attendu 401)", rec.Code)
	}
	// Le succès a remis le compteur à zéro : un seul échec de plus (le rejeu) n'a pas verrouillé.
	if blocked, _ := h.lim().blocked(userKey(user)); blocked {
		t.Error("un rejeu isolé ne doit pas verrouiller un compte dont le compteur venait d'être remis à zéro")
	}
}

func TestMFALimiter_WindowExpiryAndPrune(t *testing.T) {
	l := newMFALimiter()
	k := userKey("u")
	for i := 0; i < mfaMaxFailsPerUser; i++ {
		l.fail(k)
	}
	if blocked, wait := l.blocked(k); !blocked || wait <= 0 || wait > mfaLockout {
		t.Fatalf("verrouillage attendu : %v %v", blocked, wait)
	}
	// Échéance simulée : le verrou et la fenêtre sont passés.
	l.mu.Lock()
	l.buckets[k].lockedUntil = time.Now().Add(-time.Second)
	l.buckets[k].windowStart = time.Now().Add(-2 * mfaWindow)
	l.mu.Unlock()
	if blocked, _ := l.blocked(k); blocked {
		t.Error("le verrou doit expirer")
	}
	l.fail(k)
	l.mu.Lock()
	fails := l.buckets[k].fails
	l.mu.Unlock()
	if fails != 1 {
		t.Errorf("la fenêtre expirée repart de zéro : %d échecs", fails)
	}
}

// register/begin rend les options ET l'identifiant du défi : le client le renvoie à register/finish. Sans lui (il
// n'était pas renvoyé), l'inscription d'une clé de sécurité ne pouvait pas aboutir.
func TestWebAuthnRegisterBegin_ReturnsOptionsAndChallengeID(t *testing.T) {
	h, _, user := newMFAForLimit(t)
	wa, err := webauthn.New(&webauthn.Config{RPDisplayName: "GoProxify", RPID: "localhost", RPOrigins: []string{"http://localhost"}})
	if err != nil {
		t.Fatal(err)
	}
	h.WebAuthn = wa
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, 'u@x.fr', 'x', 'viewer')`, user); err != nil {
		t.Fatal(err)
	}
	tok, _ := adminauth.SignJWT(user, "jwt-secret", time.Hour)
	srv := adminauth.RequireJWT("jwt-secret")(h)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/webauthn/register/begin", nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	srv.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("begin : %d %s", rec.Code, rec.Body.String())
	}
	var out struct {
		Options struct {
			PublicKey struct {
				Challenge string `json:"challenge"`
			} `json:"publicKey"`
		} `json:"options"`
		ChallengeID string `json:"challenge_id"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.ChallengeID == "" || out.Options.PublicKey.Challenge == "" {
		t.Fatalf("réponse = %s", rec.Body.String())
	}
	if out.ChallengeID == out.Options.PublicKey.Challenge {
		t.Error("l'identifiant du défi stocké n'est pas le défi WebAuthn lui-même")
	}
	// Le défi enregistré appartient à cet utilisateur et se consomme une fois.
	var session webauthn.SessionData
	if err := h.Store.GetWebAuthnChallenge(context.Background(), user, out.ChallengeID, &session); err != nil {
		t.Fatalf("le défi renvoyé doit se retrouver : %v", err)
	}
	if err := h.Store.GetWebAuthnChallenge(context.Background(), user, out.ChallengeID, &session); err == nil {
		t.Error("un défi se consomme une seule fois")
	}
}

// Supprimer un utilisateur retire aussi ce qui l'authentifie : jetons API, méthodes MFA, codes de secours.
func TestDeleteUser_RemovesCredentials(t *testing.T) {
	h, _, user := newMFAForLimit(t)
	db := h.DB
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, 'x@x.fr', 'x', 'viewer'), ('admin-1', 'a@x.fr', 'x', 'admin')`, user); err != nil {
		t.Fatal(err)
	}
	db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES ('t1', ?, 'l', 'h1', 'p')`, user) //nolint:errcheck
	db.Exec(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES ('t1', 'proxies:read')`)                                 //nolint:errcheck
	db.Exec(`INSERT INTO user_backup_codes (id, user_id, code_hash) VALUES ('b1', ?, 'h')`, user)                                //nolint:errcheck
	db.Exec(`INSERT INTO user_trusted_devices (id, user_id, token_hash, name) VALUES ('d1', ?, 'h', 'n')`, user)                 //nolint:errcheck

	uh := &UsersHandler{DB: db, Log: slog.Default()}
	tok, _ := adminauth.SignJWT("admin-1", "s", time.Hour)
	req := httptest.NewRequest(http.MethodDelete, "/api/v1/users/"+user, nil)
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	adminauth.RequireJWT("s")(uh).ServeHTTP(rec, req)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("suppression : %d %s", rec.Code, rec.Body.String())
	}
	for _, tbl := range []string{"user_api_tokens", "user_mfa", "user_backup_codes", "user_trusted_devices"} {
		var n int
		db.QueryRow(`SELECT COUNT(*) FROM `+tbl+` WHERE user_id=?`, user).Scan(&n) //nolint:errcheck
		if n != 0 {
			t.Errorf("%s : %d ligne(s) restent après la suppression de l'utilisateur", tbl, n)
		}
	}
	var scopes int
	db.QueryRow(`SELECT COUNT(*) FROM user_api_token_scopes WHERE token_id='t1'`).Scan(&scopes) //nolint:errcheck
	if scopes != 0 {
		t.Errorf("%d portée(s) de jeton orphelines", scopes)
	}
}

// Changer son mot de passe révoque les autres sessions et en rend une neuve à l'appelant.
func TestChangePassword_RevokesOtherSessionsAndReturnsFreshOne(t *testing.T) {
	h, _, _ := newMFAForLimit(t)
	db := h.DB
	hash, _ := adminauth.HashPassword("ancien-mot-de-passe")
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u-pw', 'pw@x.fr', ?, 'viewer')`, hash); err != nil {
		t.Fatal(err)
	}
	secret := "jwt-pw"
	old, _ := adminauth.SignJWT("u-pw", secret, time.Hour)
	stolen, _ := adminauth.SignJWT("u-pw", secret, time.Hour)
	time.Sleep(1100 * time.Millisecond) // la révocation compte en secondes : la session doit être antérieure

	me := &MeHandler{DB: db, Log: slog.Default(), JWTSecret: secret}
	srv := adminauth.RequireAuth(secret, db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		me.changePassword(w, r, adminauth.UserIDFromContext(r.Context()))
	}))
	call := func(token, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodPost, "/api/v1/me/change-password", strings.NewReader(body))
		req.Header.Set("Authorization", "Bearer "+token)
		srv.ServeHTTP(rec, req)
		return rec
	}
	rec := call(old, `{"current_password":"ancien-mot-de-passe","new_password":"nouveau-mot-de-passe-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("changement : %d %s", rec.Code, rec.Body.String())
	}
	var out struct{ Token string }
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Token == "" {
		t.Fatalf("une session neuve doit être rendue : %s", rec.Body.String())
	}
	if rec := call(stolen, `{}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("une autre session émise avant le changement doit être révoquée : %d", rec.Code)
	}
	if rec := call(old, `{}`); rec.Code != http.StatusUnauthorized {
		t.Errorf("la session qui a changé le mot de passe est aussi remplacée : %d", rec.Code)
	}
	if rec := call(out.Token, `{"current_password":"nouveau-mot-de-passe-1","new_password":"encore-un-autre-1"}`); rec.Code != http.StatusOK {
		t.Errorf("la session neuve doit fonctionner : %d %s", rec.Code, rec.Body.String())
	}
}
