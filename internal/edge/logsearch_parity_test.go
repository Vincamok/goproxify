// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edge

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"net/url"
	"path/filepath"
	"sort"
	"strconv"
	"testing"
	"time"

	"github.com/vincamok/goproxify/internal/admin/api"
	"github.com/vincamok/goproxify/internal/admin/auth"
)

// Tant que l'Admin garde une copie des lignes brutes, la recherche dans les passerelles (source=edge) doit donner les
// mêmes résultats que sa copie (source=admin) : c'est ce qui permet de basculer sans surprise (livraison 3c).
// Le pipeline est complet : la passerelle écrit, le flux numéroté alimente l'Admin, les deux routes répondent.
func TestSearchOnTheGatewayMatchesTheAdminCopy(t *testing.T) {
	dir := t.TempDir()
	gw := newStreamGateway(t, filepath.Join(dir, "gw"))
	admin := newAdminSide(t, dir)
	t.Cleanup(admin.stop)
	admin.start(t, gw.url)
	gw.mixed("n", 90)
	waitUntil(t, "les lignes à l'Admin", func() bool { return admin.count(t, `path LIKE '/n/%'`) == 90 })

	if _, err := admin.db.Exec(`INSERT INTO users (id, email, password_hash, role) VALUES ('u1', 'root@test', 'x', 'superadmin')`); err != nil {
		t.Fatal(err)
	}
	if _, err := admin.db.Exec(`INSERT INTO tokens (id, token, role, node_name, node_endpoint) VALUES (?, 'tok', 'edge', 'gw-stream', ?)`, streamEdgeID, gw.url); err != nil {
		t.Fatal(err)
	}
	lh := &api.LogsHandler{Log: admin.quiet, Store: admin.store, DB: admin.db}
	mux := http.NewServeMux()
	mux.Handle("/api/v1/logs", lh)
	mux.Handle("/api/v1/logs/", lh)
	jwt, _ := auth.SignJWT("u1", "e2e-secret", time.Hour)
	h := auth.RequireJWT("e2e-secret")(mux)

	// paths parcourt toutes les pages d'une source et rend l'ensemble des chemins, trié.
	paths := func(source string, q url.Values) []string {
		t.Helper()
		var out []string
		cursor, before := "", ""
		for pages := 0; pages < 50; pages++ {
			v := url.Values{}
			for k, vs := range q {
				v[k] = vs
			}
			v.Set("source", source)
			v.Set("page_size", "25")
			v.Set("kind", "access")
			if cursor != "" {
				v.Set("cursor", cursor)
			}
			if before != "" {
				v.Set("before_id", before)
			}
			req := httptest.NewRequest(http.MethodGet, "/api/v1/logs?"+v.Encode(), nil)
			req.Header.Set("Authorization", "Bearer "+jwt)
			rec := httptest.NewRecorder()
			h.ServeHTTP(rec, req)
			if rec.Code != http.StatusOK {
				t.Fatalf("%s : code %d : %s", source, rec.Code, rec.Body.String())
			}
			var resp struct {
				HasMore bool   `json:"has_more"`
				Cursor  string `json:"cursor"`
				LastID  int64  `json:"last_id"`
				Entries []struct {
					Path string `json:"path"`
				} `json:"entries"`
			}
			if err := json.Unmarshal(rec.Body.Bytes(), &resp); err != nil {
				t.Fatal(err)
			}
			for _, e := range resp.Entries {
				out = append(out, e.Path)
			}
			if !resp.HasMore {
				break
			}
			cursor = resp.Cursor
			before = ""
			if source == "admin" {
				before = itoa64(resp.LastID)
			}
		}
		sort.Strings(out)
		return out
	}

	for name, q := range map[string]url.Values{
		"sans filtre":       {},
		"erreurs serveur":   {"status": {"5xx"}},
		"redirections":      {"status": {"3xx"}},
		"un domaine":        {"domain": {"d1.example.com"}},
		"domaine et code":   {"domain": {"d2.example.com"}, "status": {"404"}},
		"texte libre":       {"search": {"/n/4"}},
		"chemin":            {"path": {"/n/1"}},
		"méthode":           {"method": {"GET"}},
		"aucun résultat":    {"domain": {"absent.example.com"}},
		"exclure l'interne": {"exclude_internal": {"1"}},
	} {
		fromAdmin, fromEdge := paths("admin", q), paths("edge", q)
		if len(fromAdmin) != len(fromEdge) {
			t.Errorf("%s : %d lignes depuis l'Admin, %d depuis la passerelle", name, len(fromAdmin), len(fromEdge))
			continue
		}
		for i := range fromAdmin {
			if fromAdmin[i] != fromEdge[i] {
				t.Errorf("%s : ligne %d différente (%s / %s)", name, i, fromAdmin[i], fromEdge[i])
				break
			}
		}
	}
}

func itoa64(n int64) string { return strconv.FormatInt(n, 10) }
