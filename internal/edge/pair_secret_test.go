// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/middleware"
	"github.com/vincamok/goproxify/internal/edge/tokens"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
	"github.com/vincamok/goproxify/internal/pairing"
)

func newPairServer(t *testing.T) *Server {
	t.Helper()
	ts, err := tokens.Open(filepath.Join(t.TempDir(), "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { ts.Close() })
	s := testEdgeServer()
	s.tokenStore = ts
	s.wsHub = edgews.NewHub("hub-secret", slog.New(slog.DiscardHandler))
	return s
}

func pairOnce(s *Server, remote, secret string) int {
	req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair", strings.NewReader(`{"secret":"`+secret+`","node_name":"n1","role":"agent"}`))
	req.RemoteAddr = remote
	rr := httptest.NewRecorder()
	s.handleEdgePair(rr, req)
	return rr.Code
}

func TestEdgePair_AcceptsDerivedKeyAndRootUnlessRefused(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	s := newPairServer(t)

	if c := pairOnce(s, "10.0.0.1:1111", pairing.AgentKey(root)); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("clé dérivée refusée : %d", c)
	}
	if c := pairOnce(s, "10.0.0.2:1111", root); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("le secret racine doit rester accepté pendant la migration : %d", c)
	}
	t.Setenv("GPX_AGENT_PAIRING_ROOT", "false")
	if c := pairOnce(s, "10.0.0.3:1111", root); c != http.StatusForbidden {
		t.Fatalf("racine acceptée malgré GPX_AGENT_PAIRING_ROOT=false : %d", c)
	}
	if c := pairOnce(s, "10.0.0.4:1111", pairing.AgentKey(root)); c != http.StatusOK && c != http.StatusCreated {
		t.Fatalf("la clé dérivée doit rester acceptée : %d", c)
	}
}

func TestEdgePair_SecretGuessingIsLockedOut(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	pairAttempts = nilSafeLimiter()
	s := newPairServer(t)

	for i := 0; i < 5; i++ {
		if c := pairOnce(s, "192.0.2.50:4000", "mauvais"); c != http.StatusForbidden {
			t.Fatalf("essai %d : %d, attendu 403", i, c)
		}
	}
	if c := pairOnce(s, "192.0.2.50:4000", pairing.AgentKey(root)); c != http.StatusTooManyRequests {
		t.Fatalf("après 5 échecs même le bon secret doit être refusé : %d", c)
	}
}

func nilSafeLimiter() *middleware.AuthFailLimiter { return middleware.NewAuthFailLimiter() }

func TestAgentInternalAuthSendsDerivedKeyNotRoot(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	req := httptest.NewRequest(http.MethodPost, "http://agent:8001/internal/v1/command", nil)
	setAgentInternalAuth(req)
	got := req.Header.Get("Authorization")
	if strings.Contains(got, root) || got != "Bearer "+pairing.AgentKey(root) {
		t.Fatalf("Authorization = %q : le secret racine ne doit jamais partir vers un Agent", got)
	}
}
