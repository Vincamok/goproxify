// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/edge/surface"
)

// adminReq est une requête d'un administrateur sans périmètre, comme l'authentification la poserait.
func adminReq(t *testing.T, h *SecurityHandler, method, target string, body io.Reader) *http.Request {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES ('root','root@x.fr','x','admin')`); err != nil {
		t.Fatal(err)
	}
	r := httptest.NewRequest(method, target, body)
	return r.WithContext(auth.WithUserID(r.Context(), "root"))
}

// scopedUser crée un administrateur limité à un domaine, en lecture seule ou en écriture.
func scopedUser(t *testing.T, h *SecurityHandler, id, domain, mode string) {
	t.Helper()
	if _, err := h.DB.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES (?, ?, 'x', 'admin')`, id, id+"@x.fr"); err != nil {
		t.Fatal(err)
	}
	if _, err := h.DB.Exec(`INSERT INTO user_scopes (id, user_id, scope_type, scope_value, access_mode) VALUES (?, ?, 'domain', ?, ?)`,
		id+"-s", id, domain, mode); err != nil {
		t.Fatal(err)
	}
}

func surfaceAs(t *testing.T, h *SecurityHandler, user, method, target string, body any) (int, map[string]any) {
	t.Helper()
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	r := httptest.NewRequest(method, target, &buf)
	r = r.WithContext(auth.WithUserID(r.Context(), user))
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, r)
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

// scopeFixture : deux proxys appris par la passerelle, app.test (p1) et secret.autre.io (p2), et un administrateur limité à *.test.
func scopeFixture(t *testing.T, mode string) *SecurityHandler {
	t.Helper()
	h, paris, _ := surfaceHandler(t)
	h.Proxies = &ProxiesHandler{DB: h.DB}
	paris.Surface.Proxies = append(paris.Surface.Proxies, surface.Summary{Route: "p2", Host: "secret.autre.io", Mode: "learn", Learned: 50})
	paris.Reports["p2"] = surface.Report{Route: "p2", Host: "secret.autre.io", Mode: "learn", Members: 1, Learned: 50}
	for id, host := range map[string]string{"p1": "app.test", "p2": "secret.autre.io"} {
		if _, err := h.DB.Exec(`INSERT INTO proxies (id, name, config) VALUES (?, ?, ?)`, id, host, `{"host":"`+host+`","backends":[{"url":"http://10.0.0.1:80"}]}`); err != nil {
			t.Fatal(err)
		}
	}
	scopedUser(t, h, "scoped", "*.test", mode)
	if _, err := h.DB.Exec(`INSERT OR IGNORE INTO users (id, email, password_hash, role) VALUES ('root','root@x.fr','x','admin')`); err != nil {
		t.Fatal(err)
	}
	return h
}

// La liste de surface ne montre que les proxys du périmètre ; un admin sans périmètre les voit tous.
func TestSurfaceListIsRestrictedToTheUserScope(t *testing.T) {
	h := scopeFixture(t, "write")
	routes := func(user string) []string {
		code, out := surfaceAs(t, h, user, http.MethodGet, "/api/v1/security/surface", nil)
		if code != http.StatusOK {
			t.Fatalf("liste : %d %v", code, out)
		}
		var got []string
		for _, g := range out["gateways"].([]any) {
			for _, p := range g.(map[string]any)["proxies"].([]any) {
				got = append(got, p.(map[string]any)["route"].(string))
			}
		}
		return got
	}
	if got := routes("scoped"); len(got) != 1 || got[0] != "p1" {
		t.Fatalf("seul p1 est dans le périmètre : %v", got)
	}
	if got := routes("root"); len(got) != 2 {
		t.Fatalf("l'admin sans périmètre voit tout : %v", got)
	}
}

// Hors périmètre, un proxy est introuvable pour toutes les lectures de surface.
func TestSurfaceReadsRefuseAProxyOutsideTheScope(t *testing.T) {
	h := scopeFixture(t, "write")
	for _, sub := range []string{"report", "suggestions", "proposals", "openapi"} {
		if code, _ := surfaceAs(t, h, "scoped", http.MethodGet, "/api/v1/security/surface/"+sub+"?route=p2", nil); code != http.StatusNotFound {
			t.Errorf("%s hors périmètre : %d", sub, code)
		}
		if code, _ := surfaceAs(t, h, "scoped", http.MethodGet, "/api/v1/security/surface/"+sub+"?route=secret.autre.io", nil); code != http.StatusNotFound {
			t.Errorf("%s par l'hôte hors périmètre : %d", sub, code)
		}
	}
	if code, out := surfaceAs(t, h, "scoped", http.MethodGet, "/api/v1/security/surface/report?route=p1", nil); code != http.StatusOK {
		t.Fatalf("dans le périmètre : %d %v", code, out)
	}
}

// Les écritures de surface (réinitialiser, accepter, passer en block, relâcher) sont refusées hors périmètre, simulation
// comprise, et à un compte qui ne peut que lire dans son périmètre.
func TestSurfaceWritesRefuseOutsideTheScopeAndReadOnlyGrants(t *testing.T) {
	h := scopeFixture(t, "write")
	scopedUser(t, h, "reader", "*.test", "read")
	enforce := map[string]any{"reasons": []string{"unknown_path"}, "dry_run": true}
	accept := map[string]any{"all_high": true, "dry_run": true}

	writes := []struct {
		name, target string
		body         any
	}{
		{"reset", "/api/v1/security/surface/reset?route=", nil},
		{"enforce", "/api/v1/security/surface/enforce?route=", enforce},
		{"accept", "/api/v1/security/surface/accept?route=", accept},
		{"relax", "/api/v1/security/surface/relax?route=", nil},
	}
	for _, w := range writes {
		if code, _ := surfaceAs(t, h, "scoped", http.MethodPost, w.target+"p2", w.body); code != http.StatusNotFound {
			t.Errorf("%s hors périmètre : %d", w.name, code)
		}
		if code, _ := surfaceAs(t, h, "reader", http.MethodPost, w.target+"p1", w.body); code != http.StatusForbidden {
			t.Errorf("%s en lecture seule : %d", w.name, code)
		}
	}
	if code, out := surfaceAs(t, h, "scoped", http.MethodPost, "/api/v1/security/surface/reset?route=p1", nil); code != http.StatusOK {
		t.Fatalf("reset dans le périmètre : %d %v", code, out)
	}
}

