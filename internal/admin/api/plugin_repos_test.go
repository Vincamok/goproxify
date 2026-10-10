// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/edge/plugins"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

func entryFor(name, version string, wasm []byte, signer ed25519.PrivateKey) map[string]any {
	sum := sha256.Sum256(wasm)
	sha := hex.EncodeToString(sum[:])
	m := plugins.Manifest{Name: name, Version: version, APIVersion: 1, Hooks: []string{"request"}}
	e := map[string]any{
		"name": name, "version": version, "description": "plugin " + name,
		"manifest": map[string]any{"name": name, "version": version, "api_version": 1, "hooks": []string{"request"}},
		"wasm_url": "/" + name + "-" + version + ".wasm", "sha256": sha,
	}
	if signer != nil {
		sig, _ := plugins.Sign(signer, m, sha)
		e["signature"] = sig
	}
	return e
}

// repoServer sert un index et les modules correspondants.
func repoServer(t *testing.T, entries []map[string]any, files map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/index.json" {
			_ = json.NewEncoder(w).Encode(map[string]any{"version": 1, "name": "test", "plugins": entries})
			return
		}
		if b, ok := files[r.URL.Path]; ok {
			_, _ = w.Write(b)
			return
		}
		http.NotFound(w, r)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func newReposHandler(t *testing.T) (*PluginReposHandler, *PluginsHandler) {
	h, _ := newPluginsHandler(t)
	return &PluginReposHandler{DB: h.DB, Log: h.Log, Plugins: h}, h
}

func rpCall(h *PluginReposHandler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	return rec
}

func addRepo(t *testing.T, h *PluginReposHandler, url string) string {
	t.Helper()
	rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos", map[string]any{"name": "test", "url": url, "allow_private": true})
	if rec.Code != http.StatusCreated {
		t.Fatalf("ajout du dépôt : %d %s", rec.Code, rec.Body.String())
	}
	var out PluginRepo
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out.ID
}

func TestRepos_URLRules(t *testing.T) {
	h, _ := newReposHandler(t)
	for name, body := range map[string]map[string]any{
		"http en clair":     {"name": "a", "url": "http://plugins.example.com/index.json"},
		"adresse interne":   {"name": "b", "url": "https://127.0.0.1/index.json"},
		"métadonnées cloud": {"name": "c", "url": "https://169.254.169.254/index.json"},
		"schéma fichier":    {"name": "d", "url": "file:///etc/passwd", "allow_private": true},
		"sans nom":          {"name": "", "url": "https://plugins.example.com/index.json"},
		"URL sans hôte":     {"name": "e", "url": "https:///index.json"},
	} {
		if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d (attendu 400)", name, rec.Code)
		}
	}
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos", map[string]any{"name": "ok", "url": "https://plugins.example.com/index.json"}); rec.Code != http.StatusCreated {
		t.Errorf("dépôt https valide : %d %s", rec.Code, rec.Body.String())
	}
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos", map[string]any{"name": "dup", "url": "https://plugins.example.com/index.json"}); rec.Code != http.StatusConflict {
		t.Errorf("doublon : %d", rec.Code)
	}
}

func TestRepos_CatalogInstallUpdate(t *testing.T) {
	h, ph := newReposHandler(t)
	v1, v2 := pt.Static(`{"action":"deny","status":401}`), pt.Static(`{"action":"deny","status":402}`)
	srv := repoServer(t, []map[string]any{entryFor("paywall", "1.0.0", v1, nil), entryFor("paywall", "1.10.0", v2, nil), entryFor("autre", "0.1.0", pt.Static(`{}`), nil)},
		map[string][]byte{"/paywall-1.0.0.wasm": v1, "/paywall-1.10.0.wasm": v2, "/autre-0.1.0.wasm": pt.Static(`{}`)})
	repoID := addRepo(t, h, srv.URL+"/index.json")

	cat := func() (entries []CatalogEntry, errs int) {
		rec := rpCall(h, http.MethodGet, "/api/v1/plugin-repos/catalog", nil)
		var out struct {
			Entries []CatalogEntry      `json:"entries"`
			Errors  []map[string]string `json:"errors"`
		}
		if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
			t.Fatalf("catalogue : %v %s", err, rec.Body.String())
		}
		return out.Entries, len(out.Errors)
	}
	entries, errs := cat()
	if errs != 0 || len(entries) != 3 || entries[0].Name != "autre" || entries[1].Version != "1.10.0" {
		t.Fatalf("catalogue = %+v (erreurs %d) : la version la plus récente doit venir d'abord (1.10.0 > 1.0.0)", entries, errs)
	}

	// Sans version : la plus récente (1.10.0, pas 1.0.0).
	rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": repoID, "name": "paywall"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("installation : %d %s", rec.Code, rec.Body.String())
	}
	var info PluginInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if info.Version != "1.10.0" {
		t.Errorf("version installée = %s", info.Version)
	}
	// Une version précise remplace l'installée (mise à jour ou retour arrière).
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": repoID, "name": "paywall", "version": "1.0.0"}); rec.Code != http.StatusOK {
		t.Fatalf("remplacement : %d %s", rec.Code, rec.Body.String())
	}
	entries, _ = cat()
	for _, e := range entries {
		if e.Name == "paywall" && e.Version == "1.10.0" && (e.InstalledVersion != "1.0.0" || !e.UpdateAvailable) {
			t.Errorf("1.10.0 devrait être proposée comme mise à jour : %+v", e)
		}
		if e.Name == "paywall" && e.Version == "1.0.0" && e.UpdateAvailable {
			t.Errorf("1.0.0 est déjà installée : %+v", e)
		}
	}
	var n int
	_ = ph.DB.QueryRow(`SELECT COUNT(1) FROM plugins WHERE name='paywall'`).Scan(&n)
	if n != 1 {
		t.Errorf("%d lignes pour paywall", n)
	}
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": repoID, "name": "inconnu"}); rec.Code != http.StatusNotFound {
		t.Errorf("plugin inconnu : %d", rec.Code)
	}
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": "nope", "name": "paywall"}); rec.Code != http.StatusNotFound {
		t.Errorf("dépôt inconnu : %d", rec.Code)
	}
}

func TestRepos_InstallRefusals(t *testing.T) {
	h, _ := newReposHandler(t)
	good := pt.Static(`{}`)
	wrongSHA := entryFor("faux", "1.0.0", good, nil)
	wrongSHA["sha256"] = strings.Repeat("0", 64)
	mismatch := entryFor("incoherent", "1.0.0", good, nil)
	mismatch["manifest"].(map[string]any)["name"] = "autre-nom"
	notWasm := entryFor("abime", "1.0.0", []byte("pas du wasm"), nil)
	missingFile := entryFor("absent", "1.0.0", good, nil)
	srv := repoServer(t, []map[string]any{wrongSHA, mismatch, notWasm, missingFile},
		map[string][]byte{"/faux-1.0.0.wasm": good, "/incoherent-1.0.0.wasm": good, "/abime-1.0.0.wasm": []byte("pas du wasm")})
	repoID := addRepo(t, h, srv.URL+"/index.json")
	for _, c := range []struct {
		name string
		want int
	}{{"faux", 400}, {"incoherent", 502}, {"abime", 400}, {"absent", 502}} {
		if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": repoID, "name": c.name}); rec.Code != c.want {
			t.Errorf("%s : %d (attendu %d) %s", c.name, rec.Code, c.want, rec.Body.String())
		}
	}
}

// Un dépôt ne confère aucune confiance : dès qu'une clé de confiance existe, une entrée non signée ou signée
// par une autre clé est refusée, comme pour une installation manuelle.
func TestRepos_SignaturePolicyApplies(t *testing.T) {
	h, ph := newReposHandler(t)
	pub, priv, _ := plugins.GenerateKey()
	_, otherPriv, _ := plugins.GenerateKey()
	wasm := pt.Static(`{}`)
	srv := repoServer(t, []map[string]any{entryFor("signe", "1.0.0", wasm, priv), entryFor("nu", "1.0.0", wasm, nil), entryFor("etranger", "1.0.0", wasm, otherPriv)},
		map[string][]byte{"/signe-1.0.0.wasm": wasm, "/nu-1.0.0.wasm": wasm, "/etranger-1.0.0.wasm": wasm})
	repoID := addRepo(t, h, srv.URL+"/index.json")
	if rec := addKey(t, ph, pub); rec.Code != http.StatusCreated {
		t.Fatalf("clé : %d", rec.Code)
	}
	for name, want := range map[string]int{"signe": http.StatusCreated, "nu": http.StatusBadRequest, "etranger": http.StatusBadRequest} {
		if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]any{"repo_id": repoID, "name": name}); rec.Code != want {
			t.Errorf("%s : %d (attendu %d) %s", name, rec.Code, want, rec.Body.String())
		}
	}
}

func TestRepos_BrokenRepoIsReportedNotFatal(t *testing.T) {
	h, _ := newReposHandler(t)
	good := pt.Static(`{}`)
	ok := repoServer(t, []map[string]any{entryFor("bon", "1.0.0", good, nil)}, map[string][]byte{"/bon-1.0.0.wasm": good})
	addRepo(t, h, ok.URL+"/index.json")
	broken := httptest.NewServer(http.NotFoundHandler())
	defer broken.Close()
	rpCall(h, http.MethodPost, "/api/v1/plugin-repos", map[string]any{"name": "casse", "url": broken.URL + "/index.json", "allow_private": true})
	rec := rpCall(h, http.MethodGet, "/api/v1/plugin-repos/catalog", nil)
	var out struct {
		Entries []CatalogEntry      `json:"entries"`
		Errors  []map[string]string `json:"errors"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	if len(out.Entries) != 1 || len(out.Errors) != 1 || out.Errors[0]["repo_name"] != "casse" {
		t.Fatalf("catalogue = %s", rec.Body.String())
	}
	repos, _ := loadRepos(t.Context(), h.DB)
	if rec := rpCall(h, http.MethodDelete, "/api/v1/plugin-repos/"+repos[0].ID, nil); rec.Code != http.StatusNoContent {
		t.Errorf("suppression : %d", rec.Code)
	}
	if rec := rpCall(h, http.MethodDelete, "/api/v1/plugin-repos/nope", nil); rec.Code != http.StatusNotFound {
		t.Errorf("suppression inconnue : %d", rec.Code)
	}
}

func TestVersionLess(t *testing.T) {
	for _, c := range []struct {
		a, b string
		less bool
	}{{"1.0.0", "1.0.1", true}, {"1.9.0", "1.10.0", true}, {"v2.0.0", "1.99.99", false}, {"1.0", "1.0.0", false}, {"1.0.0", "1.0.0", false}, {"1.0.0-beta", "1.0.0-rc", true}} {
		if got := versionLess(c.a, c.b); got != c.less {
			t.Errorf("versionLess(%s, %s) = %v", c.a, c.b, got)
		}
	}
}
