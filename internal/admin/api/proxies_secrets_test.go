// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api_test

import (
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/api"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// fakeEdge garde en mémoire la route en production et celle de la dernière révision.
type fakeEdge struct {
	mu   sync.Mutex
	prod map[string]json.RawMessage
	rev  map[string]json.RawMessage
}

func (f *fakeEdge) handler() http.Handler {
	env := func(id string, cfg json.RawMessage, status string) map[string]any {
		var host struct {
			Host string `json:"host"`
		}
		_ = json.Unmarshal(cfg, &host)
		return map[string]any{"id": id, "host": host.Host, "revision": "r1", "status": status, "enabled": true, "config": cfg}
	}
	mux := http.NewServeMux()
	mux.HandleFunc("GET /internal/v1/proxies", func(w http.ResponseWriter, _ *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		list := []map[string]any{}
		for id, cfg := range f.prod {
			list = append(list, env(id, cfg, "production"))
		}
		_ = json.NewEncoder(w).Encode(map[string]any{"production": list})
	})
	mux.HandleFunc("GET /internal/v1/proxies/{id}", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		cfg, ok := f.prod[r.PathValue("id")]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_ = json.NewEncoder(w).Encode(env(r.PathValue("id"), cfg, "production"))
	})
	mux.HandleFunc("POST /internal/v1/proxies/revisions", func(w http.ResponseWriter, r *http.Request) {
		var b struct {
			ID     string          `json:"id"`
			Config json.RawMessage `json:"config"`
		}
		_ = json.NewDecoder(r.Body).Decode(&b)
		f.mu.Lock()
		f.rev[b.ID] = b.Config
		f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(env(b.ID, b.Config, "pending"))
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/dry-run", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		_ = json.NewEncoder(w).Encode(env(r.PathValue("id"), f.rev[r.PathValue("id")], "validated"))
	})
	mux.HandleFunc("POST /internal/v1/proxies/{id}/revisions/{rev}/promote", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		id := r.PathValue("id")
		f.prod[id] = f.rev[id]
		_ = json.NewEncoder(w).Encode(env(id, f.prod[id], "production"))
	})
	return mux
}

// Les secrets d'une route (OAuth, LDAP, URL signées, Basic…) ne sortent jamais en clair de l'API ; renvoyer le
// masque conserve la valeur en production, et un masque sans valeur d'origine est refusé.
func TestProxies_RouteSecretsAreMaskedAndKept(t *testing.T) {
	edge := &fakeEdge{prod: map[string]json.RawMessage{}, rev: map[string]json.RawMessage{}}
	srv := httptest.NewServer(edge.handler())
	defer srv.Close()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "p.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('su','su@x.fr','x','superadmin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint, rbac_role) VALUES ('t1','tok','edge','edge1',?, 'operator')`, srv.URL); err != nil {
		t.Fatal(err)
	}
	h := adminauth.RequireJWT("secret")(&api.ProxiesHandler{DB: db, Log: slog.Default()})

	const cfg = `{"host":"a.exemple.fr","type":"http","backends":[{"url":"http://127.0.0.1:1","weight":1}],"lb":"round_robin",
"auth":{"mode":"basic","basic_users":[{"username":"alice","password":"PW-ALICE"}]},"signed_url":{"enabled":true,"secret":"SIGN-SECRET"}}`
	rec := doAs(h, http.MethodPost, "/api/v1/proxies", `{"config":`+cfg+`}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body.String())
	}
	if strings.Contains(rec.Body.String(), "PW-ALICE") || strings.Contains(rec.Body.String(), "SIGN-SECRET") {
		t.Errorf("la réponse de création renvoie des secrets : %s", rec.Body.String())
	}
	var created struct{ ID string }
	_ = json.Unmarshal(rec.Body.Bytes(), &created)
	if !strings.Contains(string(edge.prod[created.ID]), "SIGN-SECRET") {
		t.Fatalf("la passerelle doit recevoir les vraies valeurs : %s", edge.prod[created.ID])
	}

	for _, path := range []string{"/api/v1/proxies", "/api/v1/proxies/" + created.ID} {
		out := doAs(h, http.MethodGet, path, "").Body.String()
		if !strings.Contains(out, "a.exemple.fr") || strings.Contains(out, "PW-ALICE") || strings.Contains(out, "SIGN-SECRET") || !strings.Contains(out, "alice") {
			t.Errorf("GET %s : %s", path, out)
		}
	}

	var got struct{ Config json.RawMessage }
	_ = json.Unmarshal(doAs(h, http.MethodGet, "/api/v1/proxies/"+created.ID, "").Body.Bytes(), &got)
	edited := strings.Replace(string(got.Config), `"round_robin"`, `"least_conn"`, 1)
	if rec := doAs(h, http.MethodPut, "/api/v1/proxies/"+created.ID, `{"config":`+edited+`}`); rec.Code != http.StatusOK {
		t.Fatalf("modification : %d %s", rec.Code, rec.Body.String())
	}
	prod := string(edge.prod[created.ID])
	if !strings.Contains(prod, "SIGN-SECRET") || !strings.Contains(prod, "PW-ALICE") || !strings.Contains(prod, "least_conn") || strings.Contains(prod, "••••") {
		t.Errorf("modification : secrets perdus ou masque publié : %s", prod)
	}

	masked := `{"host":"b.exemple.fr","type":"http","backends":[{"url":"http://127.0.0.1:1","weight":1}],"signed_url":{"enabled":true,"secret":"••••••••"}}`
	if rec := doAs(h, http.MethodPost, "/api/v1/proxies", `{"config":`+masked+`}`); rec.Code != http.StatusBadRequest {
		t.Errorf("masque sans valeur d'origine accepté à la création : %d", rec.Code)
	}
}
