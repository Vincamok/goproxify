// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
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
)

func permsFixture(t *testing.T) (*sql.DB, func(h http.Handler, method, path, user string, body any) *httptest.ResponseRecorder) {
	t.Helper()
	db := openSQLDatesDB(t)
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('sa','sa@t','x','superadmin'), ('a','a@t','x','admin'),
			('dpo','dpo@t','x','dpo'), ('direct','d@t','x','user'), ('member','m@t','x','user'), ('plain','p@t','x','user')`,
		`INSERT INTO user_permissions (user_id, permission) VALUES ('direct','gdpr:reveal')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique'), ('ops','Ops')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('legal','member')`,
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

// Un admin ne peut ni accorder le droit de révélation (rôle dpo, permission, équipe) ni prendre
// la main sur un compte qui le détient — sinon il l'exercerait par procuration.
func TestRevealRightIsGrantedBySuperadminOnly(t *testing.T) {
	db, do := permsFixture(t)
	users := &UsersHandler{DB: db, Log: slog.Default()}
	teams := &TeamsHandler{DB: db, Log: slog.Default()}
	newUser := func(email string, extra map[string]any) map[string]any {
		m := map[string]any{"email": email, "password": "pw-test-1234", "role": "user"}
		for k, v := range extra {
			m[k] = v
		}
		return m
	}
	cases := []struct {
		name         string
		h            http.Handler
		method, path string
		user         string
		body         any
		want         int
	}{
		{"admin crée un dpo", users, http.MethodPost, "/api/v1/users", "a", newUser("x1@t", map[string]any{"role": "dpo"}), http.StatusForbidden},
		{"admin crée avec permission", users, http.MethodPost, "/api/v1/users", "a", newUser("x2@t", map[string]any{"permissions": []string{"gdpr:reveal"}}), http.StatusForbidden},
		{"admin crée un user", users, http.MethodPost, "/api/v1/users", "a", newUser("x3@t", nil), http.StatusCreated},
		{"permission inconnue", users, http.MethodPost, "/api/v1/users", "sa", newUser("x4@t", map[string]any{"permissions": []string{"logs:write"}}), http.StatusBadRequest},
		{"superadmin crée un dpo", users, http.MethodPost, "/api/v1/users", "sa", newUser("x5@t", map[string]any{"role": "dpo"}), http.StatusCreated},
		{"admin passe un user en dpo", users, http.MethodPut, "/api/v1/users/plain", "a", map[string]any{"email": "p@t", "role": "dpo"}, http.StatusForbidden},
		{"admin accorde la permission", users, http.MethodPut, "/api/v1/users/plain", "a", map[string]any{"email": "p@t", "role": "user", "permissions": []string{"gdpr:reveal"}}, http.StatusForbidden},
		{"admin modifie un user ordinaire", users, http.MethodPut, "/api/v1/users/plain", "a", map[string]any{"email": "p2@t", "role": "user", "permissions": []string{}}, http.StatusNoContent},
		{"admin modifie un dpo", users, http.MethodPut, "/api/v1/users/dpo", "a", map[string]any{"email": "dpo@t", "role": "dpo"}, http.StatusForbidden},
		{"admin change le mdp du superadmin", users, http.MethodPut, "/api/v1/users/sa/password", "a", map[string]any{"password": "pw-test-5678"}, http.StatusForbidden},
		{"admin change le mdp d'un membre d'équipe RGPD", users, http.MethodPut, "/api/v1/users/member/password", "a", map[string]any{"password": "pw-test-5678"}, http.StatusForbidden},
		{"admin supprime un détenteur direct", users, http.MethodDelete, "/api/v1/users/direct", "a", nil, http.StatusForbidden},
		{"superadmin change le mdp d'un dpo", users, http.MethodPut, "/api/v1/users/dpo/password", "sa", map[string]any{"password": "pw-test-5678"}, http.StatusNoContent},
		{"superadmin accorde la permission", users, http.MethodPut, "/api/v1/users/plain", "sa", map[string]any{"email": "p2@t", "role": "user", "permissions": []string{"gdpr:reveal"}}, http.StatusNoContent},
		{"admin ajoute un membre à l'équipe RGPD", teams, http.MethodPost, "/api/v1/teams/legal/members", "a", map[string]any{"user_id": "a"}, http.StatusForbidden},
		{"admin retire un membre de l'équipe RGPD", teams, http.MethodDelete, "/api/v1/teams/legal/members/member", "a", nil, http.StatusForbidden},
		{"admin supprime l'équipe RGPD", teams, http.MethodDelete, "/api/v1/teams/legal", "a", nil, http.StatusForbidden},
		{"admin ajoute un membre à une équipe ordinaire", teams, http.MethodPost, "/api/v1/teams/ops/members", "a", map[string]any{"user_id": "a"}, http.StatusNoContent},
		{"admin accorde la permission à une équipe", teams, http.MethodPut, "/api/v1/teams/ops/permissions", "a", map[string]any{"permissions": []string{"gdpr:reveal"}}, http.StatusForbidden},
		{"superadmin accorde la permission à une équipe", teams, http.MethodPut, "/api/v1/teams/ops/permissions", "sa", map[string]any{"permissions": []string{"gdpr:reveal"}}, http.StatusNoContent},
	}
	for _, c := range cases {
		if rec := do(c.h, c.method, c.path, c.user, c.body); rec.Code != c.want {
			t.Errorf("%s : status %d, attendu %d (%s)", c.name, rec.Code, c.want, rec.Body)
		}
	}

	var detail struct {
		Permissions          []string `json:"permissions"`
		EffectivePermissions []string `json:"effective_permissions"`
	}
	json.Unmarshal(do(users, http.MethodGet, "/api/v1/users/plain", "sa", nil).Body.Bytes(), &detail) //nolint:errcheck
	if !slices.Equal(detail.Permissions, []string{"gdpr:reveal"}) || !slices.Equal(detail.EffectivePermissions, []string{"gdpr:reveal"}) {
		t.Errorf("GET /users/plain : %+v", detail)
	}
	// L'admin, devenu membre de « ops » avant que l'équipe ne reçoive le droit, le détient désormais.
	var me struct {
		Permissions []string `json:"permissions"`
	}
	json.Unmarshal(do(&MeHandler{DB: db, Log: slog.Default()}, http.MethodGet, "/api/v1/me", "a", nil).Body.Bytes(), &me) //nolint:errcheck
	if !slices.Equal(me.Permissions, []string{"gdpr:reveal"}) {
		t.Errorf("GET /me (admin membre de ops) : permissions %v", me.Permissions)
	}
	var n int
	db.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action = 'set_permissions'`).Scan(&n) //nolint:errcheck
	if n != 3 {
		t.Errorf("audit set_permissions : %d entrées, attendu 3 (création dpo, user, équipe)", n)
	}
}

func TestRevealByDelegatedHolders(t *testing.T) {
	f := newRGPDFixture(t)
	for _, q := range []string{
		`INSERT INTO users (id, email, password_hash, role) VALUES ('dpo','dpo@t','x','dpo'), ('member','m@t','x','user'), ('plain','p@t','x','user')`,
		`INSERT INTO teams (id, name) VALUES ('legal','Juridique')`,
		`INSERT INTO team_permissions (team_id, permission) VALUES ('legal','gdpr:reveal')`,
		`INSERT INTO team_members (team_id, user_id) VALUES ('legal','member')`,
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
