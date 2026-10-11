// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package agent

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/pairing"
)

func discardLogger() *slog.Logger {
	return slog.New(slog.DiscardHandler)
}

func TestInternalAPIRequiresAuth(t *testing.T) {
	api := newInternalAPI(0, nil, discardLogger())
	api.setAuthTokens("secret-token")

	req := httptest.NewRequest(http.MethodPost, "/internal/v1/command", strings.NewReader(`{"action":"rescan"}`))
	req.Header.Set("Content-Type", "application/json")
	rr := httptest.NewRecorder()
	api.handleCommand(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sans Bearer: status=%d want 401", rr.Code)
	}
}

func TestInternalAPIAcceptsBearer(t *testing.T) {
	api := newInternalAPI(0, nil, discardLogger())
	api.setAuthTokens("secret-token")
	// discovery nil → rescan = 503 mais auth OK
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/command", strings.NewReader(`{"action":"rescan"}`))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer secret-token")
	rr := httptest.NewRecorder()
	api.handleCommand(rr, req)
	if rr.Code == http.StatusUnauthorized {
		t.Fatal("Bearer valide ne doit pas être 401")
	}
	if rr.Code != http.StatusServiceUnavailable {
		t.Fatalf("status=%d want 503 (discovery nil)", rr.Code)
	}
}

func TestInternalAPIFailClosedWithoutTokens(t *testing.T) {
	api := newInternalAPI(0, nil, discardLogger())
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/command", strings.NewReader(`{"action":"rescan"}`))
	req.Header.Set("Authorization", "Bearer anything")
	rr := httptest.NewRecorder()
	api.handleCommand(rr, req)
	if rr.Code != http.StatusUnauthorized {
		t.Fatalf("sans tokens configurés: status=%d want 401", rr.Code)
	}
}

func TestInternalAPIAcceptsDerivedKeyFromAdminAndGateway(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	call := func(api *internalAPI, bearer string) int {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/command", strings.NewReader(`{"action":"rescan"}`))
		req.Header.Set("Authorization", "Bearer "+bearer)
		rr := httptest.NewRecorder()
		api.handleCommand(rr, req)
		return rr.Code
	}
	key := pairing.AgentKey(root)

	migrated := newInternalAPI(0, nil, discardLogger())
	migrated.setAuthTokens(pairing.AgentAccepts(key)...)
	if call(migrated, key) == http.StatusUnauthorized {
		t.Fatal("un Agent migré doit accepter la clé dérivée")
	}
	if call(migrated, root) != http.StatusUnauthorized {
		t.Fatal("un Agent migré ne doit pas accepter le secret racine : il ne le connaît pas, et un appelant qui le présente n'est pas l'Admin")
	}

	legacy := newInternalAPI(0, nil, discardLogger())
	legacy.setAuthTokens(pairing.AgentAccepts(root)...)
	if call(legacy, key) == http.StatusUnauthorized || call(legacy, root) == http.StatusUnauthorized {
		t.Fatal("un Agent non migré doit accepter la clé dérivée (nouvelle passerelle) et le secret racine (ancienne)")
	}
}
