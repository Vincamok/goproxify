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

// goproxify teams access add part d'un profil du catalogue, y ajoute niveaux et périmètre, et crée l'accès.
func TestTeamsAccessAddBuildsTheAccess(t *testing.T) {
	var got map[string]any
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.URL.Path == "/api/v1/rights/catalog" {
			w.Write([]byte(`{"profiles":[{"id":"operations","label":"Exploitation","levels":{"proxies":"operate","logs":"read"},"permissions":[]}]}`)) //nolint:errcheck
			return
		}
		path = r.Method + " " + r.URL.Path
		json.NewDecoder(r.Body).Decode(&got) //nolint:errcheck
		w.WriteHeader(http.StatusCreated)
		w.Write([]byte(`{"id":"acc-1"}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "teams", "access", "add", "ops", "-profile", "operations", "-level", "alerts=ack,logs=export",
		"-label", "env=prod", "-domain", "*.corp.io", "-environment", "prod", "-tag", "lan", "-allow", "certs:deploy",
		"-admin-url", srv.URL, "-token", "t"}
	runTeams()

	if path != "POST /api/v1/teams/ops/accesses" {
		t.Fatalf("appel : %s", path)
	}
	levels, _ := got["levels"].(map[string]any)
	if levels["proxies"] != "operate" || levels["alerts"] != "ack" || levels["logs"] != "export" {
		t.Fatalf("les niveaux explicites complètent le profil et le surchargent : %v", levels)
	}
	if got["name"] != "Exploitation" {
		t.Fatalf("nom par défaut = libellé du profil : %v", got["name"])
	}
	perimeter, _ := got["perimeter"].(map[string]any)
	labels, _ := perimeter["labels"].(map[string]any)
	group, _ := perimeter["group"].(map[string]any)
	if perimeter["domain"] != "*.corp.io" || labels["env"] != "prod" || group["environment"] != "prod" || group["tag"] != "lan" {
		t.Fatalf("périmètre : %v", perimeter)
	}
	if perms, _ := got["permissions"].([]any); len(perms) != 1 || perms[0] != "certs:deploy" {
		t.Fatalf("permissions : %v", got["permissions"])
	}
}

func TestPerimeterFromFlagsRefusesABadLabel(t *testing.T) {
	if _, err := perimeterFromFlags(map[string]string{"-label": "env"}); err == nil {
		t.Fatal("clé=valeur attendu")
	}
	p, err := perimeterFromFlags(map[string]string{})
	if err != nil || len(p) != 0 {
		t.Fatalf("aucun critère = périmètre vide : %v %v", p, err)
	}
}
