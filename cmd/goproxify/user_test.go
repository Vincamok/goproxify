// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"slices"
	"testing"
)

// L'API lit « role » : le CLI envoyait « platform_role », si bien que -role était ignoré.
func TestUserCreateSendsRoleAndPermissions(t *testing.T) {
	var got struct {
		Role        string   `json:"role"`
		Permissions []string `json:"permissions"`
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		json.NewDecoder(r.Body).Decode(&got) //nolint:errcheck
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"u1"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "user", "create", "-email", "dpo@example.test", "-password", "pw-test-1234",
		"-role", "dpo", "--permissions", "gdpr:reveal", "-admin-url", srv.URL, "-token", "t"}
	runUser()

	if got.Role != "dpo" || !slices.Equal(got.Permissions, []string{"gdpr:reveal"}) {
		t.Fatalf("payload role=%q permissions=%v", got.Role, got.Permissions)
	}
}

func TestPermissionsFlag(t *testing.T) {
	if _, ok := permissionsFlag(map[string]string{}); ok {
		t.Fatal("flag absent : ok attendu false")
	}
	if p, ok := permissionsFlag(map[string]string{"-permissions": "none"}); !ok || len(p) != 0 || p == nil {
		t.Fatalf("none : %v %v (liste vide non nulle attendue, pour retirer les permissions)", p, ok)
	}
}
