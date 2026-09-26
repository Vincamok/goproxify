// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

type recordingPusher struct {
	mu   sync.Mutex
	sent map[string]api.PortalConfig
}

func (p *recordingPusher) PushPortal(_ context.Context, edgeName string, payload any) {
	p.mu.Lock()
	defer p.mu.Unlock()
	if p.sent == nil {
		p.sent = map[string]api.PortalConfig{}
	}
	p.sent[edgeName] = payload.(api.PortalConfig)
}

func portalFixture(t *testing.T) (*sql.DB, *archstore.Store, api.GroupResolver) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "portal.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	s := archstore.New(t.TempDir())
	for _, n := range []archstore.NodeEntry{
		{ID: "dn_f", Role: "edge", Name: "frontal", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1", "portal": true}`)},
		{ID: "dn_b", Role: "edge", Name: "backup", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1", "portal": false}`)},
		{ID: "dn_s", Role: "edge", Name: "seul", Config: json.RawMessage(`{"cluster": false, "portal": true}`)},
	} {
		if err := s.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	return db, s, api.NewGroupResolver(s, db)
}

func portalReq(h http.Handler, method, url, body string) (int, string) {
	rec := do(h, method, url, body)
	return rec.Code, rec.Body.String()
}

func TestPortalConfigIsSharedByTheHAGroup(t *testing.T) {
	db, _, groups := portalFixture(t)
	pusher := &recordingPusher{}
	h := &api.PortalHandler{DB: db, Log: slog.Default(), Pusher: pusher, Groups: groups}

	code, body := portalReq(h, http.MethodPut, "/api/v1/portal?edge=frontal",
		`{"enabled":true,"public_host":"acces.example.fr","ha_session_mode":"shared","ha_key":"injection","ha_group":"x"}`)
	if code != http.StatusOK {
		t.Fatalf("PUT: %d %s", code, body)
	}
	if strings.Contains(body, "injection") {
		t.Fatal("la clé de réplication ne doit jamais être renvoyée à l'UI")
	}

	// tous les membres reçoivent la config du groupe, chacun avec son propre nom
	if len(pusher.sent) != 2 {
		t.Fatalf("push attendu sur les 2 membres, reçu %v", pusher.sent)
	}
	front, back := pusher.sent["frontal"], pusher.sent["backup"]
	if front.EdgeName != "frontal" || back.EdgeName != "backup" {
		t.Fatalf("chaque membre reçoit son nom: %q %q", front.EdgeName, back.EdgeName)
	}
	if front.PublicHost != "acces.example.fr" || back.PublicHost != "acces.example.fr" {
		t.Fatal("la config du groupe doit être identique sur les membres")
	}
	// l'activation reste une propriété du nœud (wizard) : backup est en attente
	if !front.Enabled || front.HAStandby {
		t.Fatalf("frontal héberge le portail: %+v", front)
	}
	if back.Enabled || !back.HAStandby {
		t.Fatalf("backup est en attente (portail:false dans le wizard): %+v", back)
	}
	if front.HAGroup != "ha-1" || len(front.HAMembers) != 2 || front.HASessionMode != "shared" {
		t.Fatalf("infos de groupe: %+v", front)
	}
	if front.HAKey == "" || front.HAKey != back.HAKey || front.HAKey == "injection" {
		t.Fatal("une clé de groupe unique, générée par l'Admin, est attendue sur chaque membre")
	}

	// lue depuis l'autre membre : même config, sans secret
	code, body = portalReq(h, http.MethodGet, "/api/v1/portal?edge=backup", "")
	if code != http.StatusOK || !strings.Contains(body, `"public_host":"acces.example.fr"`) || strings.Contains(body, "ha_key") {
		t.Fatalf("GET backup: %d %s", code, body)
	}

	// une passerelle hors groupe garde sa propre config et n'a pas de clé
	pusher.sent = nil
	_, _ = portalReq(h, http.MethodPut, "/api/v1/portal?edge=seul", `{"enabled":true,"public_host":"seul.example.fr"}`)
	solo := pusher.sent["seul"]
	if len(pusher.sent) != 1 || solo.HAGroup != "" || solo.HAKey != "" || solo.HASessionMode != "" {
		t.Fatalf("hors groupe: %+v", pusher.sent)
	}
}

func TestPortalSessionModeDefaultsToSticky(t *testing.T) {
	db, _, groups := portalFixture(t)
	h := &api.PortalHandler{DB: db, Log: slog.Default(), Groups: groups}
	_, _ = portalReq(h, http.MethodPut, "/api/v1/portal?edge=frontal", `{"enabled":true,"ha_session_mode":"n'importe quoi"}`)
	_, body := portalReq(h, http.MethodGet, "/api/v1/portal?edge=backup", "")
	if !strings.Contains(body, `"ha_session_mode":"sticky"`) {
		t.Fatalf("mode par défaut sticky attendu: %s", body)
	}
}

func TestPortalDestinationsAndUsersFollowTheGroup(t *testing.T) {
	db, _, groups := portalFixture(t)
	pusher := &recordingPusher{}
	h := &api.PortalHandler{DB: db, Log: slog.Default(), Pusher: pusher, Groups: groups}
	_, _ = portalReq(h, http.MethodPut, "/api/v1/portal?edge=frontal", `{"enabled":true}`)

	// une destination créée en visant « backup » appartient au groupe
	code, body := portalReq(h, http.MethodPost, "/api/v1/portal/destinations",
		`{"edge_name":"backup","kind":"ssh","name":"nas","host":"192.0.2.50","port":22}`)
	if code != http.StatusOK {
		t.Fatalf("création destination: %d %s", code, body)
	}
	for _, edge := range []string{"frontal", "backup"} {
		_, list := portalReq(h, http.MethodGet, "/api/v1/portal/destinations?edge="+edge, "")
		if !strings.Contains(list, `"name":"nas"`) {
			t.Errorf("destination absente pour %s: %s", edge, list)
		}
	}
	for _, edge := range []string{"frontal", "backup"} {
		if got := pusher.sent[edge].Catalog; len(got) != 1 || got[0].Name != "nas" {
			t.Errorf("catalogue poussé à %s: %+v", edge, got)
		}
	}

	// un utilisateur du portail rattaché au groupe est poussé à tous les membres
	_, _ = db.Exec(`INSERT INTO portal_users (id, email, status, home_edge) VALUES ('u1','alice@example.fr','active','group:ha-1')`)
	for _, edge := range []string{"frontal", "backup"} {
		payload := api.BuildPortalPayload(db, groups, edge)
		if len(payload.Users) != 1 || payload.Users[0].Email != "alice@example.fr" {
			t.Errorf("utilisateurs du groupe pour %s: %+v", edge, payload.Users)
		}
	}
}

func TestMigratePortalGroupsAttachesLegacyMemberData(t *testing.T) {
	db, _, groups := portalFixture(t)
	ctx := context.Background()
	// données d'avant les groupes : par passerelle, l'une désignée par nom, l'autre par id de token
	_, _ = db.Exec(`INSERT INTO tokens (id, token, token_hash, role, node_name) VALUES ('tok-b','x','h1','edge','backup')`)
	_ = admindb.SetSetting(db, "portal.config.frontal", `{"enabled":true,"public_host":"front.example.fr"}`)
	_ = admindb.SetSetting(db, "portal.config.tok-b", `{"enabled":true,"public_host":"autre.example.fr"}`)
	_, _ = db.Exec(`INSERT INTO portal_destinations (id, edge_name, kind, name, host, port) VALUES ('d1','frontal','ssh','nas','192.0.2.50',22)`)
	_, _ = db.Exec(`INSERT INTO portal_destinations (id, edge_name, kind, name, host, port) VALUES ('d2','tok-b','ssh','nas','192.0.2.50',22)`)
	_, _ = db.Exec(`INSERT INTO portal_destinations (id, edge_name, kind, name, host, port) VALUES ('d3','tok-b','ssh','autre','192.0.2.51',22)`)
	_, _ = db.Exec(`INSERT INTO portal_users (id, email, status, home_edge) VALUES ('u1','a@example.fr','active','tok-b')`)

	api.MigratePortalGroups(ctx, db, groups, slog.New(slog.NewTextHandler(discard{}, nil)))

	if got := admindb.GetSetting(db, "portal.config.group:ha-1", ""); !strings.Contains(got, "front.example.fr") {
		t.Fatalf("le groupe reprend le premier membre du fichier: %s", got)
	}
	if admindb.GetSetting(db, "portal.config.tok-b", "") == "" {
		t.Fatal("les configs propres aux passerelles ne doivent pas être effacées")
	}
	var n int
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_destinations WHERE edge_name='group:ha-1'`).Scan(&n)
	if n != 2 {
		t.Fatalf("2 destinations attendues dans le groupe (doublon retiré), reçu %d", n)
	}
	var home string
	_ = db.QueryRow(`SELECT home_edge FROM portal_users WHERE id='u1'`).Scan(&home)
	if home != "group:ha-1" {
		t.Fatalf("utilisateur rattaché au groupe, reçu %q", home)
	}
	// idempotent
	api.MigratePortalGroups(ctx, db, groups, slog.New(slog.NewTextHandler(discard{}, nil)))
	_ = db.QueryRow(`SELECT COUNT(*) FROM portal_destinations WHERE edge_name='group:ha-1'`).Scan(&n)
	if n != 2 {
		t.Fatalf("la migration doit être idempotente, reçu %d", n)
	}
}
