// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/vincamok/goproxify/internal/admin/pluginlib"
)

// Un Admin neuf, sans dépôt configuré, propose déjà des plugins : ceux qu'il embarque.
func TestBuiltinLibrary_CatalogWithoutAnyRepository(t *testing.T) {
	h, _ := newReposHandler(t)
	rec := rpCall(h, http.MethodGet, "/api/v1/plugin-repos/catalog", nil)
	if rec.Code != http.StatusOK {
		t.Fatalf("catalogue : %d %s", rec.Code, rec.Body.String())
	}
	var res struct {
		Entries []CatalogEntry `json:"entries"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	got := map[string]CatalogEntry{}
	for _, e := range res.Entries {
		got[e.Name] = e
	}
	for _, name := range []string{"path-guard", "rate-guard", "body-redact", "tcp-allow", "coraza"} {
		e, ok := got[name]
		if !ok || !e.Builtin || e.RepoID != pluginlib.RepoID || e.Description == "" || len(e.Hooks) == 0 || e.SHA256 == "" {
			t.Errorf("%s absent ou incomplet du catalogue : %+v", name, e)
		}
	}
	// Un filtre sur un autre dépôt les écarte.
	rec = rpCall(h, http.MethodGet, "/api/v1/plugin-repos/catalog?repo=un-autre", nil)
	_ = json.Unmarshal(rec.Body.Bytes(), &res)
	if len(res.Entries) != 0 {
		t.Errorf("le filtre par dépôt doit écarter les exemples intégrés : %d entrées", len(res.Entries))
	}
}

// Les exemples intégrés s'installent sans signature, même quand des clés de confiance sont enregistrées (ils font
// confiance au binaire de l'Admin) ; un paquet envoyé à la main reste soumis à la signature.
func TestBuiltinLibrary_InstallsEvenWithTrustKeysAndStillSignsOthers(t *testing.T) {
	h, ph := newReposHandler(t)
	pub, _, _ := ed25519.GenerateKey(rand.Reader)
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]string{"name": "ma-cle", "public_key": base64.StdEncoding.EncodeToString(pub)})
	keys := &PluginKeysHandler{DB: ph.DB, Log: ph.Log}
	krec := httptest.NewRecorder()
	keys.ServeHTTP(krec, httptest.NewRequest(http.MethodPost, "/api/v1/plugin-keys", &buf))
	if krec.Code != http.StatusCreated && krec.Code != http.StatusOK {
		t.Fatalf("clé de confiance : %d %s", krec.Code, krec.Body.String())
	}

	rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]string{"repo_id": pluginlib.RepoID, "name": "rate-guard"})
	if rec.Code != http.StatusCreated {
		t.Fatalf("installation d'un exemple intégré : %d %s", rec.Code, rec.Body.String())
	}
	var info PluginInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if info.SignedBy != "builtin" || info.Manifest.Name != "rate-guard" {
		t.Fatalf("info = %+v", info)
	}
	// Réinstaller met à jour sans conflit.
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]string{"repo_id": pluginlib.RepoID, "name": "rate-guard"}); rec.Code != http.StatusOK {
		t.Fatalf("réinstallation : %d %s", rec.Code, rec.Body.String())
	}
	if rec := rpCall(h, http.MethodPost, "/api/v1/plugin-repos/install", map[string]string{"repo_id": pluginlib.RepoID, "name": "inconnu"}); rec.Code != http.StatusNotFound {
		t.Fatalf("plugin inconnu : %d", rec.Code)
	}

	// Un paquet fourni par l'appelant, lui, doit toujours être signé : le champ « builtin » n'existe pas côté JSON.
	e, _ := pluginlib.Get("tcp-allow")
	forged := map[string]any{"manifest": e.Manifest, "sha256": e.SHA256, "wasm": e.Wasm, "builtin": true, "signed_by": "builtin"}
	var fb bytes.Buffer
	_ = json.NewEncoder(&fb).Encode(forged)
	prec := httptest.NewRecorder()
	ph.ServeHTTP(prec, httptest.NewRequest(http.MethodPost, "/api/v1/plugins", &fb))
	if prec.Code == http.StatusCreated {
		t.Fatal("un paquet non signé a été accepté malgré la clé de confiance")
	}
}
