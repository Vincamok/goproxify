// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"slices"
	"testing"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/logs"
	"github.com/vincamok/goproxify/internal/admin/rbac"
	"github.com/vincamok/goproxify/internal/admin/rbac/rbactest"
)

func permsFixture(t *testing.T) (*sql.DB, func(h http.Handler, method, path, user string, body any) *httptest.ResponseRecorder) {
	t.Helper()
	db := openSQLDatesDB(t)
	if err := rbac.EnsureBuiltInTeams(context.Background(), db); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('sa','sa@t','x','superadmin'), ('a','a@t','x','admin'),
			('dpo','dpo@t','x','user'), ('member','m@t','x','user'), ('plain','p@t','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique'), ('ops','Ops')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('team-dpo','dpo'), ('legal','member')`,
	} {
		if _, err := db.Exec(q); err != nil {
			t.Fatalf("%s: %v", q, err)
		}
	}
	do := func(h http.Handler, method, path, user string, body any) *httptest.ResponseRecorder {
		t.Helper()
		b, _ := json.Marshal(body)
		tok, err := adminauth.SignJWT(user, "secret", time.Hour)
		if err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest(method, path, bytes.NewReader(b))
		req.Header.Set("Authorization", "Bearer "+tok)
		rec := httptest.NewRecorder()
		adminauth.RequireJWT("secret")(h).ServeHTTP(rec, req)
		return rec
	}
	return db, do
}

// Un admin ne peut ni accorder une capacité RGPD (composer une équipe qui la porte) ni prendre la main sur un compte qui
// la détient — sinon il l'exercerait par procuration. Le rôle dpo n'existe plus : le DPO est l'équipe intégrée.
func TestCapabilitiesAreGrantedBySuperadminOnly(t *testing.T) {
	db, do := permsFixture(t)
	users := &UsersHandler{DB: db, Log: slog.Default()}
	teams := &TeamsHandler{DB: db, Log: slog.Default()}
	newUser := func(email, role string) map[string]any {
		return map[string]any{"email": email, "password": "pw-test-1234", "role": role}
	}
	cases := []struct {
		name         string
		h            http.Handler
		method, path string
		user         string
		body         any
		want         int
	}{
		{"le rôle dpo n'existe plus", users, http.MethodPost, "/api/v1/users", "sa", newUser("x1@t", "dpo"), http.StatusBadRequest},
		{"admin crée un user", users, http.MethodPost, "/api/v1/users", "a", newUser("x2@t", "user"), http.StatusCreated},
		{"admin crée un admin", users, http.MethodPost, "/api/v1/users", "a", newUser("x3@t", "admin"), http.StatusCreated},
		{"admin modifie un user ordinaire", users, http.MethodPut, "/api/v1/users/plain", "a", map[string]any{"email": "p2@t", "role": "user"}, http.StatusNoContent},
		{"admin modifie un membre de l'équipe DPO", users, http.MethodPut, "/api/v1/users/dpo", "a", map[string]any{"email": "dpo@t", "role": "user"}, http.StatusForbidden},
		{"admin change le mdp du superadmin", users, http.MethodPut, "/api/v1/users/sa/password", "a", map[string]any{"password": "pw-test-5678"}, http.StatusForbidden},
		{"admin change le mdp d'un membre d'équipe RGPD", users, http.MethodPut, "/api/v1/users/member/password", "a", map[string]any{"password": "pw-test-5678"}, http.StatusForbidden},
		{"admin supprime un membre de l'équipe DPO", users, http.MethodDelete, "/api/v1/users/dpo", "a", nil, http.StatusForbidden},
		{"superadmin change le mdp d'un membre DPO", users, http.MethodPut, "/api/v1/users/dpo/password", "sa", map[string]any{"password": "pw-test-5678"}, http.StatusNoContent},
		{"admin ajoute un membre à l'équipe DPO", teams, http.MethodPost, "/api/v1/teams/team-dpo/members", "a", map[string]any{"user_id": "a"}, http.StatusForbidden},
		{"admin retire un membre de l'équipe DPO", teams, http.MethodDelete, "/api/v1/teams/team-dpo/members/dpo", "a", nil, http.StatusForbidden},
		{"superadmin ajoute un membre à l'équipe DPO", teams, http.MethodPost, "/api/v1/teams/team-dpo/members", "sa", map[string]any{"user_id": "plain"}, http.StatusNoContent},
		{"admin ajoute un membre à une équipe qui porte une capacité", teams, http.MethodPost, "/api/v1/teams/legal/members", "a", map[string]any{"user_id": "a"}, http.StatusForbidden},
		{"admin retire un membre de l'équipe RGPD", teams, http.MethodDelete, "/api/v1/teams/legal/members/member", "a", nil, http.StatusForbidden},
		{"admin supprime l'équipe RGPD", teams, http.MethodDelete, "/api/v1/teams/legal", "a", nil, http.StatusForbidden},
		{"admin ajoute un membre à une équipe ordinaire", teams, http.MethodPost, "/api/v1/teams/ops/members", "a", map[string]any{"user_id": "a"}, http.StatusNoContent},
		{"admin accorde une capacité à une équipe", teams, http.MethodPut, "/api/v1/teams/ops/permissions", "a", map[string]any{"permissions": []string{"gdpr:reveal"}}, http.StatusForbidden},
		{"capacité inconnue", teams, http.MethodPut, "/api/v1/teams/ops/permissions", "sa", map[string]any{"permissions": []string{"logs:write"}}, http.StatusBadRequest},
		{"superadmin accorde une capacité à une équipe", teams, http.MethodPut, "/api/v1/teams/ops/permissions", "sa", map[string]any{"permissions": []string{"gdpr:reveal"}}, http.StatusNoContent},
	}
	for _, c := range cases {
		if rec := do(c.h, c.method, c.path, c.user, c.body); rec.Code != c.want {
			t.Errorf("%s : status %d, attendu %d (%s)", c.name, rec.Code, c.want, rec.Body)
		}
	}

	// L'équipe DPO est intégrée : ni renommée, ni supprimée, ni dotée d'un accès, ni d'autres capacités — même par le superadmin.
	for _, c := range []struct {
		name         string
		method, path string
		body         any
	}{
		{"renommer l'équipe DPO", http.MethodPut, "/api/v1/teams/team-dpo", map[string]any{"name": "Autre"}},
		{"supprimer l'équipe DPO", http.MethodDelete, "/api/v1/teams/team-dpo", nil},
		{"changer les capacités de l'équipe DPO", http.MethodPut, "/api/v1/teams/team-dpo/permissions", map[string]any{"permissions": []string{}}},
		{"donner un accès à l'équipe DPO", http.MethodPost, "/api/v1/teams/team-dpo/accesses", map[string]any{"name": "tout", "levels": map[string]string{"proxies": "read"}}},
	} {
		if rec := do(teams, c.method, c.path, "sa", c.body); rec.Code != http.StatusConflict {
			t.Errorf("%s : status %d, attendu 409 (%s)", c.name, rec.Code, rec.Body)
		}
	}
	var list []teamRow
	json.Unmarshal(do(teams, http.MethodGet, "/api/v1/teams", "sa", nil).Body.Bytes(), &list) //nolint:errcheck
	for _, tm := range list {
		if tm.ID == rbac.DPOTeamID && (!tm.Builtin || tm.Name != "DPO" || len(tm.Permissions) != 4) {
			t.Errorf("équipe DPO dans la liste : %+v", tm)
		}
	}

	var detail struct {
		EffectivePermissions []string `json:"effective_permissions"`
	}
	json.Unmarshal(do(users, http.MethodGet, "/api/v1/users/plain", "sa", nil).Body.Bytes(), &detail) //nolint:errcheck
	if !slices.Equal(detail.EffectivePermissions, rbac.KnownPermissions) {
		t.Errorf("GET /users/plain, devenu membre de l'équipe DPO : %+v", detail)
	}
	// L'admin, devenu membre de « ops » avant que l'équipe ne reçoive le droit, le détient désormais ; il garde aussi
	// l'export et l'effacement par son rôle.
	var me struct {
		Permissions []string `json:"permissions"`
	}
	json.Unmarshal(do(&MeHandler{DB: db, Log: slog.Default()}, http.MethodGet, "/api/v1/me", "a", nil).Body.Bytes(), &me) //nolint:errcheck
	if !slices.Equal(me.Permissions, []string{"gdpr:reveal", "gdpr:export", "gdpr:erase"}) {
		t.Errorf("GET /me (admin membre de ops) : permissions %v", me.Permissions)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'set_permissions'`).Scan(&n) //nolint:errcheck
	if n != 1 {
		t.Errorf("audit set_permissions : %d entrées, attendu 1 (équipe ops)", n)
	}
}

// L'accès effectif d'un compte dit d'où vient chaque droit ; un compte inconnu répond 404.
func TestUserAccessEndpoint(t *testing.T) {
	db, do := permsFixture(t)
	users := &UsersHandler{DB: db, Log: slog.Default()}
	if err := rbactest.Save(db, "ops", "s1", rbactest.Access("domain", "*.example.io", "write")); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO team_members (team_id, user_id) VALUES ('ops','plain')`); err != nil {
		t.Fatal(err)
	}
	var acc rbac.Access
	rec := do(users, http.MethodGet, "/api/v1/users/plain/access", "a", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("status %d (%s)", rec.Code, rec.Body)
	}
	json.Unmarshal(rec.Body.Bytes(), &acc) //nolint:errcheck
	if acc.Global || len(acc.Teams) != 1 || acc.Teams[0].Name != "Ops" || len(acc.Teams[0].Accesses) != 1 ||
		acc.Teams[0].Accesses[0].Perimeter.Domain != "*.example.io" || acc.Teams[0].Accesses[0].Levels["proxies"] != "operate" ||
		!slices.Contains(acc.Granted, "proxies:operate") {
		t.Errorf("accès effectif : %+v", acc)
	}
	if rec := do(users, http.MethodGet, "/api/v1/users/absent/access", "a", nil); rec.Code != http.StatusNotFound {
		t.Errorf("compte inconnu : %d", rec.Code)
	}
}

func TestRevealByDelegatedHolders(t *testing.T) {
	f := newRGPDFixture(t)
	if err := rbac.EnsureBuiltInTeams(context.Background(), f.db); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('dpo','dpo@t','x','user'), ('member','m@t','x','user'), ('plain','p@t','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('team-dpo','dpo'), ('legal','member')`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	f.store.SetPseudonymize(true)
	f.store.Write(logs.Entry{Status: 200, IP: "203.0.113.0", RealIP: "203.0.113.42"})
	var id int64
	f.db.QueryRow(`SELECT id FROM logs WHERE ip_enc != ''`).Scan(&id) //nolint:errcheck
	for user, want := range map[string]int{"dpo": http.StatusOK, "member": http.StatusOK, "plain": http.StatusForbidden, "a": http.StatusForbidden} {
		if rec := f.do(http.MethodPost, "/api/v1/logs/reveal-ip", user, map[string]any{"entry_id": id, "reason": "réquisition"}); rec.Code != want {
			t.Errorf("%s : status %d, attendu %d (%s)", user, rec.Code, want, rec.Body)
		}
	}
}

// L'export et l'effacement RGPD s'ouvrent aux membres de l'équipe DPO sans qu'ils soient administrateurs ; un administrateur
// les garde ; un compte ordinaire, ou le membre d'une équipe qui ne porte que la révélation, ne les a pas.
func TestExportAndEraseNeedTheirCapability(t *testing.T) {
	f := newRGPDFixture(t)
	if err := rbac.EnsureBuiltInTeams(context.Background(), f.db); err != nil {
		t.Fatal(err)
	}
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('dpo','dpo@t','x','user'), ('member','m@t','x','user'), ('plain','p@t','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('team-dpo','dpo'), ('legal','member')`,
	} {
		if _, err := f.db.Exec(q); err != nil {
			t.Fatal(err)
		}
	}
	for user, allowed := range map[string]bool{"dpo": true, "a": true, "member": false, "plain": false} {
		erase := f.do(http.MethodDelete, "/api/v1/logs/by-ip/203.0.113.7", user, nil)
		export := f.do(http.MethodPost, "/api/v1/logs/subject-export", user, map[string]any{"ip": "203.0.113.7", "reason": "demande d'accès"})
		if got := erase.Code != http.StatusForbidden; got != allowed {
			t.Errorf("%s : effacement autorisé=%v (status %d), attendu %v", user, got, erase.Code, allowed)
		}
		if got := export.Code != http.StatusForbidden; got != allowed {
			t.Errorf("%s : export autorisé=%v (status %d), attendu %v", user, got, export.Code, allowed)
		}
	}
}
