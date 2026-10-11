// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package middleware

import (
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"
)

func identityBackend(seen *http.Header) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		*seen = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	})
}

// Un utilisateur authentifié ne peut pas compléter son identité avec les en-têtes que son fournisseur ne pose pas :
// avant, seul X-Remote-User était écrasé, et un « X-Remote-Groups: admins » ou « Remote-Email: … » forgé atteignait le
// backend, qui s'y fie.
func TestSSOAuth_ForgedIdentityHeadersNeverReachTheBackend(t *testing.T) {
	forged := map[string]string{
		"X-Remote-User": "admin", "X-Remote-Name": "Le Patron", "X-Remote-Email": "admin@corp.example", "X-Remote-Groups": "admins",
		"Remote-User": "admin", "Remote-Groups": "admins", "Remote-Email": "admin@corp.example",
		"X-Forwarded-User": "admin", "X-Forwarded-Groups": "admins", "X-Auth-Request-User": "admin", "X-Auth-Request-Groups": "admins",
		"X-Webauth-User": "admin", "X-Webauth-Email": "admin@corp.example",
	}

	// OIDC : session valide pour « alice ».
	oidc := &oidcHandler{cfg: fullSSO("oidc").OIDC}
	payload, _ := json.Marshal(sessionPayload{User: "alice", Exp: time.Now().Add(time.Hour).Unix()})
	cookie := &http.Cookie{Name: oidcCookieName, Value: base64.URLEncoding.EncodeToString(oidc.sign(payload))}

	var seen http.Header
	h := SSOAuth(fullSSO("oidc"))(identityBackend(&seen))
	req := httptest.NewRequest(http.MethodGet, "http://app.example.fr/secret", nil)
	req.AddCookie(cookie)
	for k, v := range forged {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("la session valide doit passer : %d", rec.Code)
	}
	if got := seen.Get("X-Remote-User"); got != "alice" {
		t.Errorf("X-Remote-User = %q, attendu l'identité de la session", got)
	}
	for k := range forged {
		if k == "X-Remote-User" {
			continue
		}
		if v := seen.Get(k); v != "" {
			t.Errorf("l'en-tête forgé %s = %q a atteint le backend", k, v)
		}
	}

	// Basic : mêmes garanties.
	var seenBasic http.Header
	hb := SSOAuth(fullSSO("basic"))(identityBackend(&seenBasic))
	req = httptest.NewRequest(http.MethodGet, "http://app.example.fr/secret", nil)
	req.SetBasicAuth("u", "p")
	for k, v := range forged {
		req.Header.Set(k, v)
	}
	rec = httptest.NewRecorder()
	hb.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("basic valide : %d", rec.Code)
	}
	for k := range forged {
		if k == "X-Remote-User" {
			continue
		}
		if v := seenBasic.Get(k); v != "" {
			t.Errorf("basic : l'en-tête forgé %s = %q a atteint le backend", k, v)
		}
	}
	if got := seenBasic.Get("X-Remote-User"); got == "admin" {
		t.Errorf("basic : X-Remote-User forgé conservé : %q", got)
	}
}
