// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package admin

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/pairing"
)

func TestPair_AgentKeyOpensAgentPairingOnly(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Server{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil)), loginLimit: newLoginLimiter()}

	pair := func(remote, secret, role, name string) int {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair", strings.NewReader(`{"secret":"`+secret+`","node_name":"`+name+`","role":"`+role+`"}`))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.handlePair(rec, req)
		return rec.Code
	}
	key := pairing.AgentKey(root)
	declareAutoAccept(t, db, "agent", "agent-a")
	declareAutoAccept(t, db, "edge", "edge-b")
	declareAutoAccept(t, db, "agent", "agent-legacy")

	if c := pair("10.1.0.1:1", key, "agent", "agent-a"); c != http.StatusOK {
		t.Fatalf("un Agent déclaré doit pouvoir s'appairer avec la clé dérivée : %d", c)
	}
	if c := pair("10.1.0.2:1", key, "edge", "edge-a"); c != http.StatusForbidden {
		t.Fatalf("la clé d'Agent ne doit pas appairer une passerelle : %d", c)
	}
	if c := pair("10.1.0.3:1", root, "edge", "edge-b"); c != http.StatusOK {
		t.Fatalf("une passerelle déclarée s'appaire avec le secret racine : %d", c)
	}
	if c := pair("10.1.0.4:1", root, "agent", "agent-legacy"); c != http.StatusOK {
		t.Fatalf("un Agent déclaré non migré (secret racine) doit encore pouvoir s'appairer : %d", c)
	}
	if c := pair("10.1.0.5:1", key, "agent", "agent-inconnu"); c != http.StatusAccepted {
		t.Fatalf("un Agent non déclaré attend l'approbation de l'opérateur : %d", c)
	}
	if c := pair("10.1.0.6:1", root, "edge", "edge-inconnue"); c != http.StatusAccepted {
		t.Fatalf("une passerelle non déclarée attend l'approbation de l'opérateur : %d", c)
	}
}

func TestPair_AgentWithRootRefusedWhenConfigured(t *testing.T) {
	const root = "secret-racine-0123456789abcdef"
	t.Setenv("GPX_PAIRING_SECRET", root)
	t.Setenv("GPX_AGENT_PAIRING_ROOT", "false")
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	s := &Server{db: db, log: slog.New(slog.NewTextHandler(io.Discard, nil)), loginLimit: newLoginLimiter()}
	pair := func(remote, secret, role string) int {
		req := httptest.NewRequest(http.MethodPost, "/internal/v1/pair", strings.NewReader(`{"secret":"`+secret+`","node_name":"n","role":"`+role+`"}`))
		req.RemoteAddr = remote
		rec := httptest.NewRecorder()
		s.handlePair(rec, req)
		return rec.Code
	}
	if c := pair("10.2.0.1:1", root, "agent"); c != http.StatusForbidden {
		t.Fatalf("un Agent ne doit plus pouvoir s'appairer avec la racine : %d", c)
	}
	declareAutoAccept(t, db, "agent", "n")
	declareAutoAccept(t, db, "edge", "n")
	if c := pair("10.2.0.2:1", pairing.AgentKey(root), "agent"); c != http.StatusOK {
		t.Fatalf("la clé dérivée reste acceptée : %d", c)
	}
	if c := pair("10.2.0.3:1", root, "edge"); c != http.StatusOK {
		t.Fatalf("une passerelle s'appaire toujours avec la racine : %d", c)
	}
}
