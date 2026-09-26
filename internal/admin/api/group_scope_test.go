// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	_ "modernc.org/sqlite"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/archstore"
)

func groupFixture(t *testing.T, dbName string) (*sql.DB, *archstore.Store) {
	t.Helper()
	db, err := sql.Open("sqlite", "file:"+dbName+"?mode=memory&cache=shared")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE settings (key TEXT PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	s := archstore.New(t.TempDir())
	for _, n := range []archstore.NodeEntry{
		{ID: "dn_f", Role: "edge", Name: "frontal", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
		{ID: "dn_b", Role: "edge", Name: "backup", Config: json.RawMessage(`{"cluster": true, "cluster_group": "ha-1"}`)},
		{ID: "dn_s", Role: "edge", Name: "seul", Config: json.RawMessage(`{"cluster": false}`)},
	} {
		if err := s.Upsert(n); err != nil {
			t.Fatal(err)
		}
	}
	return db, s
}

func do(h http.Handler, method, url, body string) *httptest.ResponseRecorder {
	req := httptest.NewRequest(method, url, strings.NewReader(body))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func TestSentinelConfigFollowsTheHAGroup(t *testing.T) {
	db, store := groupFixture(t, "grp_sentinel")
	var pushed []string
	h := &api.SecurityHandler{
		DB: db, Groups: store,
		OnThreatConfigChange: func(scope string, _ any) { pushed = append(pushed, scope) },
	}

	// activation via un membre du groupe
	if rec := do(h, http.MethodPut, "/api/v1/security/threat-config?edge=frontal", `{"enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d %s", rec.Code, rec.Body.String())
	}
	if len(pushed) != 1 || pushed[0] != "group:ha-1" {
		t.Fatalf("le push doit viser le groupe, reçu %v", pushed)
	}

	// l'autre membre (par nom ou par id) voit la même configuration
	for _, ref := range []string{"backup", "dn_b", "dn_f"} {
		if got := strings.TrimSpace(do(h, http.MethodGet, "/api/v1/security/threat-config?edge="+ref, "").Body.String()); got != `{"enabled":true}` {
			t.Errorf("membre %s : %q, attendu la config du groupe", ref, got)
		}
	}
	// une passerelle hors groupe n'est pas concernée
	if got := strings.TrimSpace(do(h, http.MethodGet, "/api/v1/security/threat-config?edge=seul", "").Body.String()); got != `{"enabled":false}` {
		t.Fatalf("hors groupe : %q", got)
	}
	// et une écriture hors groupe reste sur sa passerelle
	pushed = nil
	do(h, http.MethodPut, "/api/v1/security/threat-config?edge=seul", `{"enabled":true}`)
	if len(pushed) != 1 || pushed[0] != "seul" {
		t.Fatalf("hors groupe : push attendu sur la passerelle, reçu %v", pushed)
	}
	if got := strings.TrimSpace(do(h, http.MethodGet, "/api/v1/security/threat-config?edge=backup", "").Body.String()); got != `{"enabled":true}` {
		t.Fatalf("le groupe ne doit pas être touché par une passerelle hors groupe : %q", got)
	}
}

func TestReadFallsBackToLegacyPerEdgeThenGlobal(t *testing.T) {
	db, store := groupFixture(t, "grp_fallback")
	h := &api.SecurityHandler{DB: db, Groups: store}

	_, _ = db.Exec(`INSERT INTO settings(key, value) VALUES('threat_engine_config','{"enabled":true,"mode":"detect"}')`)
	if got := strings.TrimSpace(do(h, http.MethodGet, "/api/v1/security/threat-config?edge=seul", "").Body.String()); got != `{"enabled":true,"mode":"detect"}` {
		t.Fatalf("repli sur la config globale attendu, reçu %q", got)
	}
	// valeur propre à une passerelle du groupe, antérieure aux groupes
	_, _ = db.Exec(`INSERT INTO settings(key, value) VALUES('threat_engine_config:dn_b','{"enabled":true,"mode":"block"}')`)
	if got := strings.TrimSpace(do(h, http.MethodGet, "/api/v1/security/threat-config?edge=dn_b", "").Body.String()); got != `{"enabled":true,"mode":"block"}` {
		t.Fatalf("valeur propre (avant groupes) attendue, reçu %q", got)
	}
}

func TestMigrateGroupSettingsAdoptsFirstMemberAndKeepsMemberValues(t *testing.T) {
	db, store := groupFixture(t, "grp_migrate")
	ctx := context.Background()
	_, _ = db.Exec(`INSERT INTO settings(key, value) VALUES('threat_engine_config:dn_f','{"enabled":true,"mode":"block"}')`)
	_, _ = db.Exec(`INSERT INTO settings(key, value) VALUES('threat_engine_config:dn_b','{"enabled":false}')`)
	_, _ = db.Exec(`INSERT INTO settings(key, value) VALUES('ips_provider:backup','crowdsec')`)

	api.MigrateGroupSettings(ctx, db, store, slog.New(slog.NewTextHandler(discard{}, nil)))

	read := func(k string) string {
		var v string
		_ = db.QueryRow(`SELECT value FROM settings WHERE key=?`, k).Scan(&v)
		return v
	}
	if got := read("threat_engine_config:group:ha-1"); got != `{"enabled":true,"mode":"block"}` {
		t.Fatalf("le groupe reprend le premier membre du fichier, reçu %q", got)
	}
	if got := read("ips_provider:group:ha-1"); got != "crowdsec" {
		t.Fatalf("fournisseur IPS repris de backup, reçu %q", got)
	}
	if read("threat_engine_config:dn_b") != `{"enabled":false}` {
		t.Fatal("les valeurs propres aux passerelles ne doivent pas être effacées")
	}
	// idempotent : une valeur de groupe existante n'est jamais écrasée
	_, _ = db.Exec(`UPDATE settings SET value='{"enabled":false}' WHERE key='threat_engine_config:group:ha-1'`)
	api.MigrateGroupSettings(ctx, db, store, slog.New(slog.NewTextHandler(discard{}, nil)))
	if got := read("threat_engine_config:group:ha-1"); got != `{"enabled":false}` {
		t.Fatalf("valeur de groupe écrasée : %q", got)
	}
}

type discard struct{}

func (discard) Write(p []byte) (int, error) { return len(p), nil }

func TestGroupResolverUnderstandsTokenIDs(t *testing.T) {
	db, store := groupFixture(t, "grp_tokenid")
	if _, err := db.Exec(`CREATE TABLE tokens (id TEXT PRIMARY KEY, node_name TEXT, role TEXT)`); err != nil {
		t.Fatal(err)
	}
	// le token du Core principal n'a pas l'id de son nœud dans architecture.json
	_, _ = db.Exec(`INSERT INTO tokens(id, node_name, role) VALUES('ae4e-token','frontal','edge')`)
	g := api.NewGroupResolver(store, db)

	if got := g.GroupOf("ae4e-token"); got != "ha-1" {
		t.Fatalf("un id de token doit se résoudre par le nom du nœud, reçu %q", got)
	}
	if got := g.GroupOf("frontal"); got != "ha-1" {
		t.Fatalf("par nom : %q", got)
	}
	if got := g.GroupOf("inconnu"); got != "" {
		t.Fatalf("inconnu : %q", got)
	}

	// le réglage écrit via l'id du token est celui du groupe
	h := &api.SecurityHandler{DB: db, Groups: g}
	if rec := do(h, http.MethodPut, "/api/v1/security/threat-config?edge=ae4e-token", `{"enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT: %d", rec.Code)
	}
	if got := strings.TrimSpace(do(h, http.MethodGet, "/api/v1/security/threat-config?edge=backup", "").Body.String()); got != `{"enabled":true}` {
		t.Fatalf("le membre backup doit voir la config écrite via le token de frontal, reçu %q", got)
	}
}
