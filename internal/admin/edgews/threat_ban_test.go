// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"encoding/json"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

func TestHandleThreatBanKeepsTheBanSource(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "admin.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	m := NewManager("", db, slog.Default())
	exp := time.Now().Add(time.Hour).UTC().Format(time.RFC3339)

	for _, p := range []edgeWS.ThreatBanPayload{
		{IP: "203.0.113.1", Reason: "threat: rate", ExpiresAt: exp, NodeName: "paris"},
		{IP: "203.0.113.2", Reason: "coraza: trop de refus", ExpiresAt: exp, NodeName: "paris", Source: "plugin:coraza"},
		{IP: "203.0.113.3", Reason: "forgé", ExpiresAt: exp, NodeName: "paris", Source: "fail2ban"},
		{IP: "203.0.113.4", Reason: "vide", ExpiresAt: exp, NodeName: "paris", Source: "plugin:"},
	} {
		raw, _ := json.Marshal(p)
		m.handleThreatBan(raw)
	}

	want := map[string]string{
		"203.0.113.1": "threat",
		"203.0.113.2": "plugin:coraza",
		"203.0.113.3": "threat", // seule une source de plugin est reprise du message
		"203.0.113.4": "threat",
	}
	for ip, src := range want {
		var id, bansSrc, histSrc string
		if err := db.QueryRow(`SELECT id, source FROM security_bans WHERE ip = ?`, ip).Scan(&id, &bansSrc); err != nil {
			t.Fatalf("%s : %v", ip, err)
		}
		if err := db.QueryRow(`SELECT source FROM security_ban_history WHERE ip = ? AND action = 'banned'`, ip).Scan(&histSrc); err != nil {
			t.Fatalf("%s historique : %v", ip, err)
		}
		if bansSrc != src || histSrc != src || id != src+"-"+ip {
			t.Errorf("%s : id=%q source=%q historique=%q, attendu source %q", ip, id, bansSrc, histSrc, src)
		}
	}
}
