// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// L'API lit « role » : le CLI envoyait « platform_role », si bien que -role était ignoré. Les comptes ne portent plus de
// permissions en propre : la capacité RGPD s'obtient par l'équipe DPO, la création n'en envoie donc aucune.
func TestUserCreateSendsRoleOnly(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got) //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"u1"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "user", "create", "-email", "ops@example.test", "-password", "pw-test-1234",
		"-role", "admin", "-admin-url", srv.URL, "-token", "t"}
	runUser()

	if got["role"] != "admin" {
		t.Fatalf("payload %v", got)
	}
	if _, has := got["permissions"]; has {
		t.Fatalf("un compte ne porte plus de permissions en propre : %v", got)
	}
}

// goproxify user access lit GET /api/v1/users/{id}/access.
func TestUserAccessReadsTheEffectiveAccess(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path = r.URL.Path
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"role":"user","global":false,"grants":[],"permissions":[]}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "user", "access", "u1", "-admin-url", srv.URL, "-token", "t"}
	runUser()

	if path != "/api/v1/users/u1/access" {
		t.Fatalf("chemin appelé : %q", path)
	}
}

func TestPermissionsFlag(t *testing.T) {
	if _, ok := permissionsFlag(map[string]string{}); ok {
		t.Fatal("flag absent : ok attendu false")
	}
	if p, ok := permissionsFlag(map[string]string{"-permissions": "none"}); !ok || len(p) != 0 || p == nil {
		t.Fatalf("none : %v %v (liste vide non nulle attendue, pour retirer les capacités d'une équipe)", p, ok)
	}
}
