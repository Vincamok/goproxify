// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package auth_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func TestGeneratePAT(t *testing.T) {
	tok := auth.GeneratePAT()
	if !strings.HasPrefix(tok, auth.PATPrefix) {
		t.Fatalf("préfixe attendu %q, reçu %q", auth.PATPrefix, tok)
	}
	if !auth.IsPATToken(tok) {
		t.Fatal("IsPATToken devrait être true")
	}
	hexPart := strings.TrimPrefix(tok, auth.PATPrefix)
	if len(hexPart) != 32 {
		t.Fatalf("hex len=%d", len(hexPart))
	}
	if auth.GeneratePAT() == tok {
		t.Fatal("deux PAT ne doivent pas être identiques")
	}
}

func TestHashAndPreviewPAT(t *testing.T) {
	plain := auth.GeneratePAT()
	h1 := auth.HashPAT(plain)
	h2 := auth.HashPAT(plain)
	if h1 != h2 || h1 == "" {
		t.Fatal("hash instable ou vide")
	}
	if auth.HashPAT(plain+"x") == h1 {
		t.Fatal("hash devrait changer")
	}
	prev := auth.PATPreview(plain)
	if !strings.Contains(prev, "…") || strings.Contains(prev, plain) {
		t.Fatalf("aperçu invalide: %q", prev)
	}
}

func TestLookupPATAndRequirePAT(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	userID := "user-1"
	_, err = db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		userID, "u@test.local", "x", "admin")
	if err != nil {
		t.Fatalf("insert user: %v", err)
	}

	plain := auth.GeneratePAT()
	id := "pat-1"
	_, err = db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES (?,?,?,?,?)`,
		id, userID, "test", auth.HashPAT(plain), auth.PATPreview(plain))
	if err != nil {
		t.Fatalf("insert pat: %v", err)
	}
	_, err = db.Exec(`INSERT INTO user_api_token_scopes (token_id, scope) VALUES (?, ?)`, id, "proxies:read")
	if err != nil {
		t.Fatalf("insert scope: %v", err)
	}

	uid, tid, scopes, err := auth.LookupPAT(context.Background(), db, plain)
	if err != nil || uid != userID || tid != id {
		t.Fatalf("LookupPAT: uid=%q tid=%q err=%v", uid, tid, err)
	}
	if len(scopes) != 1 || scopes[0] != "proxies:read" {
		t.Fatalf("scopes=%v", scopes)
	}

	// Révoqué
	db.Exec(`UPDATE user_api_tokens SET revoked=1 WHERE id=?`, id)
	if _, _, _, err := auth.LookupPAT(context.Background(), db, plain); err == nil {
		t.Fatal("PAT révoqué devrait échouer")
	}

	// Nouveau PAT pour middleware
	plain2 := auth.GeneratePAT()
	id2 := "pat-2"
	db.Exec(`UPDATE user_api_tokens SET revoked=0 WHERE id=?`, id) // cleanup
	_, err = db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES (?,?,?,?,?)`,
		id2, userID, "m", auth.HashPAT(plain2), auth.PATPreview(plain2))
	if err != nil {
		t.Fatalf("insert pat2: %v", err)
	}

	h := auth.RequirePAT(db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if auth.UserIDFromContext(r.Context()) != userID {
			t.Errorf("userID=%q", auth.UserIDFromContext(r.Context()))
		}
		if !auth.IsPATAuth(r.Context()) {
			t.Error("attendu PAT auth")
		}
		w.WriteHeader(http.StatusNoContent)
	}))

	// JWT rejeté
	req := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req.Header.Set("Authorization", "Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.e30.x")
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("JWT sur MCP: code=%d", rr.Code)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/mcp", nil)
	req2.Header.Set("Authorization", "Bearer "+plain2)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != http.StatusNoContent {
		t.Fatalf("PAT valide: code=%d body=%s", rr2.Code, rr2.Body.String())
	}
}

func TestRequireAuthJWTOrPAT(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	defer db.Close()

	userID := "user-2"
	db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, ?, ?)`,
		userID, "u2@test.local", "x", "viewer")

	secret := "test-secret"
	jwt, err := auth.SignJWT(userID, secret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	plain := auth.GeneratePAT()
	db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES (?,?,?,?,?)`,
		"p3", userID, "t", auth.HashPAT(plain), auth.PATPreview(plain))

	var gotKind string
	h := auth.RequireAuth(secret, db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotKind = auth.AuthKindFromContext(r.Context())
		w.WriteHeader(200)
	}))

	req := httptest.NewRequest(http.MethodGet, "/api/v1/proxies", nil)
	req.Header.Set("Authorization", "Bearer "+jwt)
	rr := httptest.NewRecorder()
	h.ServeHTTP(rr, req)
	if rr.Code != 200 || gotKind != auth.AuthKindJWT {
		t.Fatalf("JWT: code=%d kind=%q", rr.Code, gotKind)
	}

	req2 := httptest.NewRequest(http.MethodGet, "/api/v1/proxies", nil)
	req2.Header.Set("Authorization", "Bearer "+plain)
	rr2 := httptest.NewRecorder()
	h.ServeHTTP(rr2, req2)
	if rr2.Code != 200 || gotKind != auth.AuthKindPAT {
		t.Fatalf("PAT: code=%d kind=%q", rr2.Code, gotKind)
	}
}

func TestLookupPATExpired(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "test.db")
	db, err := admindb.Open(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u','e','x','admin')`)
	plain := auth.GeneratePAT()
	past := time.Now().UTC().Add(-time.Hour)
	db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix, expires_at) VALUES (?,?,?,?,?,?)`,
		"pe", "u", "e", auth.HashPAT(plain), auth.PATPreview(plain), past)
	if _, _, _, err := auth.LookupPAT(context.Background(), db, plain); err == nil {
		t.Fatal("expiré devrait échouer")
	}
}

// Le jeton API et la session d'un compte supprimé ne servent plus : rien ne les révoquait, et un JWT vaut 24 h.
func TestDeletedUserSessionAndPATAreRejected(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u9', 'u9@test.local', 'x', 'viewer')`); err != nil {
		t.Fatal(err)
	}
	secret := "test-secret"
	jwt, _ := auth.SignJWT("u9", secret, time.Hour)
	plain := auth.GeneratePAT()
	if _, err := db.Exec(`INSERT INTO user_api_tokens (id, user_id, label, token_hash, token_prefix) VALUES ('p9','u9','t',?,?)`, auth.HashPAT(plain), auth.PATPreview(plain)); err != nil {
		t.Fatal(err)
	}
	call := func(token string) int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+token)
		auth.RequireAuth(secret, db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(rec, req)
		return rec.Code
	}
	if call(jwt) != 200 || call(plain) != 200 {
		t.Fatal("un compte existant doit s'authentifier")
	}
	if _, err := db.Exec(`DELETE FROM users WHERE id='u9'`); err != nil {
		t.Fatal(err)
	}
	if code := call(jwt); code != http.StatusUnauthorized {
		t.Errorf("JWT d'un compte supprimé : %d (attendu 401)", code)
	}
	if code := call(plain); code != http.StatusUnauthorized {
		t.Errorf("PAT d'un compte supprimé : %d (attendu 401)", code)
	}
	if _, _, _, err := auth.LookupPAT(context.Background(), db, plain); err == nil {
		t.Error("LookupPAT d'un compte supprimé doit échouer (MCP)")
	}
}

// Une session émise avant tokens_valid_after est refusée ; celle émise à cet instant ou après passe.
func TestJWTRevokedByTokensValidAfter(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u7', 'u7@test.local', 'x', 'viewer')`); err != nil {
		t.Fatal(err)
	}
	secret := "test-secret"
	jwt, _ := auth.SignJWT("u7", secret, time.Hour)
	call := func() int {
		rec := httptest.NewRecorder()
		req := httptest.NewRequest(http.MethodGet, "/x", nil)
		req.Header.Set("Authorization", "Bearer "+jwt)
		auth.RequireAuth(secret, db)(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(200) })).ServeHTTP(rec, req)
		return rec.Code
	}
	if call() != http.StatusOK {
		t.Fatal("session valide refusée")
	}
	future := time.Now().Add(time.Hour).Unix() // la session a été émise avant
	if _, err := db.Exec(`UPDATE users SET tokens_valid_after=? WHERE id='u7'`, future); err != nil {
		t.Fatal(err)
	}
	if call() != http.StatusUnauthorized {
		t.Error("une session émise avant la révocation doit être refusée")
	}
	if _, err := db.Exec(`UPDATE users SET tokens_valid_after=? WHERE id='u7'`, time.Now().Add(-time.Hour).Unix()); err != nil {
		t.Fatal(err)
	}
	if call() != http.StatusOK {
		t.Error("une session émise après la date de révocation passe")
	}
	if err := auth.RevokeSessions(context.Background(), db, "u7"); err != nil {
		t.Fatal(err)
	}
	var v int64
	db.QueryRow(`SELECT tokens_valid_after FROM users WHERE id='u7'`).Scan(&v) //nolint:errcheck
	if d := time.Now().Unix() - v; d < 0 || d > 2 {
		t.Errorf("RevokeSessions doit poser la date courante : %d", v)
	}
}
