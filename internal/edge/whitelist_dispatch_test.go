// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/config"
	edgelog "github.com/vincamok/goproxify/internal/edge/logger"
	"github.com/vincamok/goproxify/internal/edge/router"
	"github.com/vincamok/goproxify/internal/edge/threat"
)

func dispatchStatus(s *Server, remote string) int {
	req := httptest.NewRequest(http.MethodGet, "http://inconnu.test/", nil)
	req.RemoteAddr = remote + ":4000"
	rec := httptest.NewRecorder()
	s.dispatch(rec, req)
	return rec.Code
}

func whitelistServer(t *testing.T, profiles []*router.IPProfile) *Server {
	t.Helper()
	s := &Server{
		cfg:          &config.EdgeConfig{},
		log:          edgelog.New("error", "text", ""),
		table:        &router.Table{},
		banStore:     router.NewBanStore(),
		profileStore: router.NewIPProfileStore(),
	}
	s.profileStore.Replace(profiles)
	s.threatEngine = threat.New(slog.New(slog.NewTextHandler(io.Discard, nil)), nil)
	s.threatEngine.UpdateConfig(threat.Config{
		Enabled:     true,
		Mode:        "block",
		CustomLists: threat.CustomListsConfig{IPs: []string{"203.0.113.0/24"}},
	})
	return s
}

// Sentinel bloque la plage ; la liste blanche des bans l'en exempte, un autre profil allow non.
func TestWhitelistExemptsFromSentinel(t *testing.T) {
	plain := whitelistServer(t, nil)
	if got := dispatchStatus(plain, "203.0.113.50"); got == http.StatusNotFound {
		t.Fatal("prérequis : Sentinel doit bloquer cette IP avant d'arriver au routage")
	}

	wl := whitelistServer(t, []*router.IPProfile{{ID: router.WhitelistProfileID, Name: "Liste blanche (bans)", Mode: "allow", CIDRs: []string{"203.0.113.50"}}})
	if got := dispatchStatus(wl, "203.0.113.50"); got != http.StatusNotFound {
		t.Fatalf("IP en liste blanche : statut %d, attendu 404 (aucune route, mais Sentinel ne bloque pas)", got)
	}
	if got := dispatchStatus(wl, "203.0.113.51"); got == http.StatusNotFound {
		t.Fatal("une autre IP de la plage doit rester bloquée par Sentinel")
	}

	other := whitelistServer(t, []*router.IPProfile{{ID: "partenaires", Name: "Partenaires", Mode: "allow", CIDRs: []string{"203.0.113.50"}}})
	if got := dispatchStatus(other, "203.0.113.50"); got == http.StatusNotFound {
		t.Fatal("un profil allow ordinaire ne doit pas exempter de Sentinel (comportement historique)")
	}
}

func TestIsWhitelisted(t *testing.T) {
	s := router.NewIPProfileStore()
	s.Replace([]*router.IPProfile{
		{ID: router.WhitelistProfileID, Mode: "allow", CIDRs: []string{"198.51.100.0/24", "2001:db8:1::/48"}},
		{ID: "partenaires", Mode: "allow", CIDRs: []string{"203.0.113.0/24"}},
		{ID: "bogus", Mode: "deny", CIDRs: []string{"192.0.2.0/24"}},
	})
	for ip, want := range map[string]bool{
		"198.51.100.9": true, "2001:db8:1::5": true,
		"203.0.113.9": false, // autre profil allow
		"192.0.2.9":   false, "8.8.8.8": false, "10.0.0.1": false, "pas-une-ip": false,
	} {
		if got := s.IsWhitelisted(ip); got != want {
			t.Errorf("IsWhitelisted(%s) = %v, attendu %v", ip, got, want)
		}
	}
	// Un profil portant l'identifiant de la liste blanche mais en mode deny n'exempte rien.
	d := router.NewIPProfileStore()
	d.Replace([]*router.IPProfile{{ID: router.WhitelistProfileID, Mode: "deny", CIDRs: []string{"198.51.100.0/24"}}})
	if d.IsWhitelisted("198.51.100.9") {
		t.Error("le mode deny ne peut pas servir de liste blanche")
	}
}
