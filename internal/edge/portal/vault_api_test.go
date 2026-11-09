// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package portal

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestPersonalTargetsForbiddenWhenDisabled(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true, AllowPersonalTargets: false}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPost, "/api/targets", strings.NewReader(
		`{"name":"vm","kind":"ssh","host":"10.0.0.1","port":22}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
}

func TestPersonalDockerTargetsForbidden(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	hash, _ := HashPassword("password1")
	_ = store.CreateUser(UserRecord{
		ID: "u1", Username: "a@b.c", PasswordHash: hash,
		Status: UserStatusActive, CreatedAt: time.Now().UTC().Format(time.RFC3339),
	})
	h := NewHTTPServer(&Config{Enabled: true, AllowPersonalTargets: true}, store, NewSessionManager(), nil, nil)
	tok := loginToken(t, h, "a@b.c", "password1")

	req := httptest.NewRequest(http.MethodPost, "/api/targets", strings.NewReader(
		`{"name":"box","kind":"docker","agent_name":"agent-1","container":"nginx"}`))
	req.Header.Set("Authorization", "Bearer "+tok)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, req)
	if rr.Code != http.StatusForbidden {
		t.Fatalf("status=%d %s", rr.Code, rr.Body.String())
	}
}


func TestAuthInfoExposesPersonalFlag(t *testing.T) {
	store := NewStore(filepath.Join(t.TempDir(), "p.gpx"), "test-secret")
	h := NewHTTPServer(&Config{Enabled: true, AllowPersonalTargets: true}, store, NewSessionManager(), nil, nil)
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodGet, "/api/auth-info", nil))
	var out map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &out)
	if out["allow_personal_targets"] != true {
		t.Fatalf("%v", out)
	}
}


func loginToken(t *testing.T, h *HTTPServer, user, pass string) string {
	t.Helper()
	rr := httptest.NewRecorder()
	h.Handler().ServeHTTP(rr, httptest.NewRequest(http.MethodPost, "/api/login", strings.NewReader(
		`{"username":"`+user+`","password":"`+pass+`"}`)))
	var login map[string]any
	_ = json.Unmarshal(rr.Body.Bytes(), &login)
	tok, _ := login["token"].(string)
	if tok == "" {
		t.Fatalf("login failed: %s", rr.Body.String())
	}
	return tok
}
