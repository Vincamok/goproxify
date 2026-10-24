// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
	"nhooyr.io/websocket"
	"nhooyr.io/websocket/wsjson"
)

// recordingEdge accepte toute connexion et retient les messages que l'Admin lui envoie.
func recordingEdge(t *testing.T) (*httptest.Server, func() []edgeWS.Message) {
	t.Helper()
	var mu sync.Mutex
	var got []edgeWS.Message
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		conn, err := websocket.Accept(w, r, nil)
		if err != nil {
			return
		}
		for {
			var m edgeWS.Message
			if wsjson.Read(r.Context(), conn, &m) != nil {
				return
			}
			mu.Lock()
			got = append(got, m)
			mu.Unlock()
		}
	}))
	t.Cleanup(srv.Close)
	return srv, func() []edgeWS.Message {
		mu.Lock()
		defer mu.Unlock()
		return append([]edgeWS.Message(nil), got...)
	}
}

func rotateFixture(t *testing.T, connected bool) (*Manager, *edgeEntry, func() []edgeWS.Message) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "rotate.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	stored, hash := auth.PrepareNodeTokenForStore("gpx_ancien_jeton")
	if _, err := db.Exec(`INSERT INTO tokens (id, token, token_hash, role, rbac_role, node_name, node_endpoint) VALUES ('dn_a', ?, ?, 'edge', 'admin', 'frontal', 'http://x:8000')`, stored, hash); err != nil {
		t.Fatal(err)
	}
	m := &Manager{db: db, log: slog.Default(), edges: map[string]*edgeEntry{}}
	srv, received := recordingEdge(t)
	entry := &edgeEntry{id: "dn_a", nodeName: "frontal"}
	if connected {
		entry.client = NewClient("dn_a", "frontal", srv.URL, "", nil, nil, nil, slog.Default())
		t.Cleanup(entry.client.Close)
		deadline := time.Now().Add(3 * time.Second)
		for !entry.client.Connected() && time.Now().Before(deadline) {
			time.Sleep(10 * time.Millisecond)
		}
		if !entry.client.Connected() {
			t.Fatal("connexion non établie")
		}
	} else {
		entry.client = &Client{log: slog.Default()}
	}
	m.edges["dn_a"] = entry
	return m, entry, received
}

func messagesOf(t *testing.T, msgs []edgeWS.Message, typ string) []string {
	t.Helper()
	var out []string
	for _, m := range msgs {
		if m.Type != typ {
			continue
		}
		var p edgeWS.AdminTokenPayload
		_ = json.Unmarshal(m.Payload, &p)
		out = append(out, p.Token)
	}
	return out
}

func waitMessages(t *testing.T, received func() []edgeWS.Message, n int) []edgeWS.Message {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if got := received(); len(got) >= n {
			return got
		}
		time.Sleep(10 * time.Millisecond)
	}
	return received()
}

// Le jeton d'une passerelle connectée est remplacé en base, poussé, et l'ancien est révoqué sur la passerelle.
func TestRotateEdgeTokenReplacesPushesAndRevokes(t *testing.T) {
	m, entry, received := rotateFixture(t, true)
	if !m.RotateEdgeToken(context.Background(), "frontal") {
		t.Fatal("la passerelle est connue")
	}
	var stored string
	if err := m.db.QueryRow(`SELECT token FROM tokens WHERE id='dn_a'`).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	fresh := auth.PlainNodeToken(stored)
	if fresh == "" || fresh == "gpx_ancien_jeton" {
		t.Fatalf("le jeton doit avoir changé : %q", fresh)
	}
	if auth.HashNodeToken(fresh) == auth.HashNodeToken("gpx_ancien_jeton") {
		t.Fatal("l'empreinte aussi")
	}

	msgs := waitMessages(t, received, 2)
	if got := messagesOf(t, msgs, edgeWS.TypeAdminToken); len(got) != 1 || got[0] != fresh {
		t.Fatalf("le nouveau jeton est poussé : %v", got)
	}
	if got := messagesOf(t, msgs, edgeWS.TypeRevokeStaleAdminTokens); len(got) != 1 || got[0] != fresh {
		t.Fatalf("la révocation garde le nouveau jeton : %v", got)
	}
	if admindb.GetSetting(m.db, pendingRevokeKey("dn_a"), "") != "" {
		t.Fatal("l'ordre est parti : plus rien en attente")
	}
	_ = entry
}

// Une passerelle hors ligne reçoit le nouveau jeton à sa reconnexion, et l'ordre de révocation reste en attente.
func TestRotateEdgeTokenIsPendingForAnOfflineEdge(t *testing.T) {
	m, entry, _ := rotateFixture(t, false)
	if !m.RotateEdgeToken(context.Background(), "dn_a") {
		t.Fatal("la passerelle est connue, par son identifiant")
	}
	if admindb.GetSetting(m.db, pendingRevokeKey("dn_a"), "") == "" {
		t.Fatal("hors ligne : la révocation reste en attente")
	}
	if len(entry.client.pending) != 1 {
		t.Fatalf("le nouveau jeton attend la reconnexion : %d message(s)", len(entry.client.pending))
	}
	if m.RotateEdgeToken(context.Background(), "inconnue") {
		t.Fatal("une passerelle inconnue n'a pas de jeton à renouveler")
	}
}
