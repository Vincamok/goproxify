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

// goproxify proxy tag relit le proxy, pose le nom et les étiquettes dans sa configuration et la renvoie en PUT.
func TestProxyTagPutsNameAndLabels(t *testing.T) {
	var put map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		if r.Method == http.MethodPut {
			json.NewDecoder(r.Body).Decode(&put) //nolint:errcheck
			w.Write([]byte(`{}`))                //nolint:errcheck
			return
		}
		w.Write([]byte(`{"enabled":true,"config":{"host":"app.corp.io","labels":{"env":"test","old":"x"}}}`)) //nolint:errcheck
	}))
	defer srv.Close()

	saved := os.Args
	defer func() { os.Args = saved }()
	os.Args = []string{"goproxify", "proxy", "tag", "p1", "env=prod", "projet=alpha", "-unset", "old", "-name", "alpha-1",
		"-admin-url", srv.URL, "-token", "t"}
	runProxy()

	cfg, _ := put["config"].(map[string]any)
	labels, _ := cfg["labels"].(map[string]any)
	if cfg["name"] != "alpha-1" || labels["env"] != "prod" || labels["projet"] != "alpha" {
		t.Fatalf("configuration envoyée : %v", cfg)
	}
	if _, kept := labels["old"]; kept {
		t.Fatalf("-unset doit retirer l'étiquette : %v", labels)
	}
	if cfg["host"] != "app.corp.io" || put["enabled"] != true {
		t.Fatalf("le reste de la configuration est conservé : %v", put)
	}
}
