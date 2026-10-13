// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mfa"
)

// « Faire confiance à cet appareil » pose un cookie HttpOnly que le navigateur renvoie à la connexion ; l'appareil
// reste reconnu après un redémarrage de l'Admin (base rouverte). Le token n'apparaît plus dans le corps de la
// réponse : l'interface ne l'enregistrait nulle part, et l'appareil n'était donc jamais reconnu.
func TestMFAChallenge_TrustDeviceSetsCookieThatSurvivesRestart(t *testing.T) {
	path := filepath.Join(t.TempDir(), "mfa.db")
	db, err := admindb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	h := &MFAHandler{DB: db, Store: mfa.NewStore(db), JWTSecret: "secret-trust"}
	secret, err := mfa.TOTPSecret()
	if err != nil {
		t.Fatal(err)
	}
	if err := h.Store.UpsertMethod(context.Background(), "user-1", mfa.MethodTOTP, map[string]string{"secret": secret}, true); err != nil {
		t.Fatal(err)
	}
	pending, err := adminauth.SignMFAPendingToken("user-1", h.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	code, _ := mfa.TOTPCode(secret)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/challenge",
		strings.NewReader(`{"mfa_token":`+jsonQuote(pending)+`,"method":"totp","code":"`+code+`","trust_device":true}`))
	req.Header.Set("X-Forwarded-Proto", "https")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("challenge : %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "device_token") {
		t.Errorf("le token d'appareil ne doit pas être lisible par le JavaScript : %s", rec.Body.String())
	}
	var cookie *http.Cookie
	for _, c := range rec.Result().Cookies() {
		if c.Name == mfa.TrustedDeviceCookie {
			cookie = c
		}
	}
	if cookie == nil || cookie.Value == "" {
		t.Fatal("cookie d'appareil de confiance absent")
	}
	if !cookie.HttpOnly || !cookie.Secure || cookie.SameSite != http.SameSiteStrictMode || cookie.Path != "/api/v1/auth" {
		t.Errorf("attributs du cookie : %+v", cookie)
	}
	if cookie.MaxAge != mfa.TrustedDeviceTTLDays*24*3600 {
		t.Errorf("MaxAge %d : le cookie doit durer autant que l'appareil de confiance", cookie.MaxAge)
	}
	db.Close()

	db2, err := admindb.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	defer db2.Close()
	if !mfa.NewStore(db2).IsTrustedDevice(context.Background(), "user-1", mfa.HashDeviceToken(cookie.Value)) {
		t.Fatal("appareil de confiance perdu après réouverture de la base")
	}
}

func TestDeviceCookieSecureOnlyOverHTTPS(t *testing.T) {
	plain := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/challenge", nil)
	if mfa.DeviceCookie(plain, "x").Secure {
		t.Error("en HTTP clair, un cookie Secure ne serait jamais renvoyé")
	}
	tls := httptest.NewRequest(http.MethodPost, "https://admin.example.com/api/v1/auth/mfa/challenge", nil)
	if !mfa.DeviceCookie(tls, "x").Secure {
		t.Error("cookie Secure attendu en HTTPS")
	}
}
