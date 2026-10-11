// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/mfa"
)

func TestLoginSend_EmailCodeIsIssuedForTheAccountAndThrottled(t *testing.T) {
	h, _, userID := newMFAForLimit(t)
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, 'alice@example.fr', 'x', 'user')`, userID); err != nil {
		t.Fatal(err)
	}
	if err := h.Store.UpsertMethod(context.Background(), userID, mfa.MethodEmail, map[string]string{"email": "alice@example.fr"}, true); err != nil {
		t.Fatal(err)
	}
	pending, err := adminauth.SignMFAPendingToken(userID, h.JWTSecret)
	if err != nil {
		t.Fatal(err)
	}
	send := func(token, method string) int {
		req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/send", strings.NewReader(`{"mfa_token":"`+token+`","method":"`+method+`"}`))
		rr := httptest.NewRecorder()
		h.loginSend(rr, req)
		return rr.Code
	}
	count := func() int {
		var n int
		h.DB.QueryRow(`SELECT COUNT(*) FROM user_mfa_challenges WHERE user_id=? AND method='email'`, userID).Scan(&n)
		return n
	}

	if c := send("pas-un-jeton", "email"); c != http.StatusUnauthorized {
		t.Fatalf("jeton invalide : %d", c)
	}
	if c := send(pending, "totp"); c != http.StatusBadRequest {
		t.Fatalf("une méthode sans envoi doit être refusée : %d", c)
	}
	if c := send(pending, "sms"); c != http.StatusBadRequest {
		t.Fatalf("une méthode non configurée doit être refusée : %d", c)
	}
	if count() != 0 {
		t.Fatal("aucun code ne doit être créé pour une demande refusée")
	}

	for i := 0; i < sendMaxPerUser; i++ {
		if c := send(pending, "email"); c != http.StatusAccepted {
			t.Fatalf("envoi %d : %d", i, c)
		}
	}
	if count() != sendMaxPerUser {
		t.Fatalf("%d codes créés, attendu %d", count(), sendMaxPerUser)
	}
	if c := send(pending, "email"); c != http.StatusTooManyRequests {
		t.Fatalf("au-delà de la limite : %d, attendu 429", c)
	}
	if count() != sendMaxPerUser {
		t.Fatal("un envoi refusé ne doit pas créer de code")
	}
}

func TestLoginSend_UnverifiedMethodSendsNothing(t *testing.T) {
	h, _, userID := newMFAForLimit(t)
	h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, 'bob@example.fr', 'x', 'user')`, userID)
	// méthode enregistrée mais jamais confirmée par son code d'activation
	if err := h.Store.UpsertMethod(context.Background(), userID, mfa.MethodEmail, map[string]string{"email": "bob@example.fr"}, false); err != nil {
		t.Fatal(err)
	}
	pending, _ := adminauth.SignMFAPendingToken(userID, h.JWTSecret)
	req := httptest.NewRequest(http.MethodPost, "/api/v1/auth/mfa/send", strings.NewReader(`{"mfa_token":"`+pending+`","method":"email"}`))
	rr := httptest.NewRecorder()
	h.loginSend(rr, req)
	if rr.Code != http.StatusBadRequest {
		t.Fatalf("méthode non vérifiée : %d, attendu 400", rr.Code)
	}
}
