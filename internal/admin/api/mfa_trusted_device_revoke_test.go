// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"database/sql"
	"encoding/json"
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

const revokeSecret = "secret-revoke"

func newRevokeDB(t *testing.T) *sql.DB {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "revoke.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	hash, _ := adminauth.HashPassword("ancien-mot-de-passe")
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES
		('u-1', 'u1@x.fr', ?, 'viewer'), ('u-2', 'u2@x.fr', ?, 'viewer'), ('admin-1', 'a@x.fr', ?, 'admin')`,
		hash, hash, hash); err != nil {
		t.Fatal(err)
	}
	store := mfa.NewStore(db)
	for _, d := range []struct{ user, hash string }{{"u-1", "h1"}, {"u-1", "h2"}, {"u-2", "h3"}} {
		if _, err := store.CreateTrustedDevice(context.Background(), d.user, d.hash, "navigateur"); err != nil {
			t.Fatal(err)
		}
	}
	return db
}

func trustedDevices(t *testing.T, db *sql.DB, userID string) []mfa.TrustedDevice {
	t.Helper()
	list, err := mfa.NewStore(db).ListTrustedDevices(context.Background(), userID)
	if err != nil {
		t.Fatal(err)
	}
	return list
}

func callAs(t *testing.T, h http.Handler, userID, method, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	tok, err := adminauth.SignJWT(userID, revokeSecret, time.Hour)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.Header.Set("Authorization", "Bearer "+tok)
	rec := httptest.NewRecorder()
	adminauth.RequireJWT(revokeSecret)(h).ServeHTTP(rec, req)
	return rec
}

func TestTrustedDevices_ListRevokeOneAndAll(t *testing.T) {
	db := newRevokeDB(t)
	h := &MFAHandler{DB: db, Store: mfa.NewStore(db), JWTSecret: revokeSecret}

	rec := callAs(t, h, "u-1", http.MethodGet, "/api/v1/auth/mfa/trusted-devices", "")
	if rec.Code != http.StatusOK {
		t.Fatalf("liste : %d %s", rec.Code, rec.Body.String())
	}
	var list []mfa.TrustedDevice
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("2 appareils attendus pour u-1 : %s", rec.Body.String())
	}
	if list[0].ExpiresAt.IsZero() || list[0].CreatedAt.IsZero() || list[0].Name == "" {
		t.Errorf("champs incomplets : %+v", list[0])
	}

	if rec := callAs(t, h, "u-2", http.MethodDelete, "/api/v1/auth/mfa/trusted-devices/"+list[0].ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("révocation par un autre utilisateur : %d", rec.Code)
	}
	if n := len(trustedDevices(t, db, "u-1")); n != 2 {
		t.Fatalf("un utilisateur ne révoque pas l'appareil d'un autre : %d restant(s)", n)
	}

	if rec := callAs(t, h, "u-1", http.MethodDelete, "/api/v1/auth/mfa/trusted-devices/"+list[0].ID, ""); rec.Code != http.StatusNoContent {
		t.Fatalf("révocation : %d", rec.Code)
	}
	if left := trustedDevices(t, db, "u-1"); len(left) != 1 || left[0].ID != list[1].ID {
		t.Fatalf("seul l'appareil révoqué disparaît : %+v", left)
	}

	if rec := callAs(t, h, "u-1", http.MethodDelete, "/api/v1/auth/mfa/trusted-devices", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("révoquer tous : %d %s", rec.Code, rec.Body.String())
	}
	if n := len(trustedDevices(t, db, "u-1")); n != 0 {
		t.Errorf("%d appareil(s) restent après « révoquer tous »", n)
	}
	if n := len(trustedDevices(t, db, "u-2")); n != 1 {
		t.Errorf("les appareils des autres utilisateurs ne sont pas touchés : %d", n)
	}
}

func TestChangePassword_RevokesTrustedDevices(t *testing.T) {
	db := newRevokeDB(t)
	me := &MeHandler{DB: db, Log: slog.Default(), JWTSecret: revokeSecret}
	rec := callAs(t, me, "u-1", http.MethodPost, "/api/v1/me/change-password",
		`{"current_password":"ancien-mot-de-passe","new_password":"nouveau-mot-de-passe-1"}`)
	if rec.Code != http.StatusOK {
		t.Fatalf("changement : %d %s", rec.Code, rec.Body.String())
	}
	if n := len(trustedDevices(t, db, "u-1")); n != 0 {
		t.Errorf("%d appareil(s) de confiance survivent au changement de mot de passe", n)
	}
	if n := len(trustedDevices(t, db, "u-2")); n != 1 {
		t.Errorf("les appareils des autres utilisateurs ne sont pas touchés : %d", n)
	}
}

func TestAdminPasswordReset_RevokesTrustedDevices(t *testing.T) {
	for _, tc := range []struct{ name, method, path, body string }{
		{"réinitialisation", http.MethodPut, "/api/v1/users/u-1/password", `{"password":"nouveau-mot-de-passe-1"}`},
		{"modification avec mot de passe", http.MethodPut, "/api/v1/users/u-1", `{"email":"u1@x.fr","role":"viewer","password":"nouveau-mot-de-passe-1"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			db := newRevokeDB(t)
			uh := &UsersHandler{DB: db, Log: slog.Default()}
			rec := callAs(t, uh, "admin-1", tc.method, tc.path, tc.body)
			if rec.Code != http.StatusNoContent && rec.Code != http.StatusOK {
				t.Fatalf("%s : %d %s", tc.name, rec.Code, rec.Body.String())
			}
			if n := len(trustedDevices(t, db, "u-1")); n != 0 {
				t.Errorf("%d appareil(s) de confiance survivent à la réinitialisation par un admin", n)
			}
			if n := len(trustedDevices(t, db, "u-2")); n != 1 {
				t.Errorf("les appareils des autres utilisateurs ne sont pas touchés : %d", n)
			}
		})
	}
}

// Les appareils restent tant qu'une méthode vérifiée demeure ; ils tombent quand la MFA est désactivée, sinon ils
// dispenseraient du second facteur dès sa réactivation.
func TestDisableMFA_RevokesTrustedDevices(t *testing.T) {
	db := newRevokeDB(t)
	h := &MFAHandler{DB: db, Store: mfa.NewStore(db), JWTSecret: revokeSecret}
	ctx := context.Background()
	if err := h.Store.UpsertMethod(ctx, "u-1", mfa.MethodTOTP, map[string]string{"secret": "x"}, true); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.UpsertMethod(ctx, "u-1", mfa.MethodEmail, map[string]string{}, true); err != nil {
		t.Fatal(err)
	}

	if rec := callAs(t, h, "u-1", http.MethodDelete, "/api/v1/auth/mfa/email", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("suppression email : %d", rec.Code)
	}
	if n := len(trustedDevices(t, db, "u-1")); n != 2 {
		t.Fatalf("une méthode vérifiée reste : les appareils sont gardés (%d)", n)
	}

	if rec := callAs(t, h, "u-1", http.MethodDelete, "/api/v1/auth/mfa/totp", ""); rec.Code != http.StatusNoContent {
		t.Fatalf("suppression TOTP : %d", rec.Code)
	}
	if n := len(trustedDevices(t, db, "u-1")); n != 0 {
		t.Errorf("%d appareil(s) de confiance survivent à la désactivation de la MFA", n)
	}
	if n := len(trustedDevices(t, db, "u-2")); n != 1 {
		t.Errorf("les appareils des autres utilisateurs ne sont pas touchés : %d", n)
	}
}
