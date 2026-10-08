// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"github.com/vincamok/goproxify/internal/edge/plugins"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

type countingPusher struct{ n atomic.Int32 }

func (c *countingPusher) PushPlugins(context.Context) { c.n.Add(1) }

func newPluginsHandler(t *testing.T) (*PluginsHandler, *countingPusher) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "plugins.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	p := &countingPusher{}
	return &PluginsHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Pusher: p}, p
}

func plCall(h *PluginsHandler, method, path string, body any) *httptest.ResponseRecorder {
	var buf bytes.Buffer
	if body != nil {
		_ = json.NewEncoder(&buf).Encode(body)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, &buf))
	return rec
}

func pluginBody(name string, wasm []byte) map[string]any {
	sum := sha256.Sum256(wasm)
	return map[string]any{
		"manifest": map[string]any{"name": name, "version": "1.0.0", "api_version": 1, "hooks": []string{"request"}},
		"sha256":   hex.EncodeToString(sum[:]),
		"wasm":     wasm,
	}
}

func TestPlugins_InstallListReplaceDelete(t *testing.T) {
	h, pusher := newPluginsHandler(t)
	wasm := pt.Static(`{"action":"deny"}`)
	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", pluginBody("geo", wasm)); rec.Code != http.StatusCreated {
		t.Fatalf("POST : %d %s", rec.Code, rec.Body.String())
	}
	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", pluginBody("geo", wasm)); rec.Code != http.StatusConflict {
		t.Errorf("doublon : %d", rec.Code)
	}
	var list []PluginInfo
	rec := plCall(h, http.MethodGet, "/api/v1/plugins", nil)
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 1 || list[0].Name != "geo" || list[0].Size != len(wasm) || list[0].OnError != "deny" {
		t.Fatalf("liste = %s (%v)", rec.Body.String(), err)
	}
	if bytes.Contains(rec.Body.Bytes(), []byte("wasm")) && bytes.Contains(rec.Body.Bytes(), []byte(`"wasm":`)) {
		t.Error("la liste expose le module")
	}
	if rec := plCall(h, http.MethodGet, "/api/v1/plugins/geo", nil); rec.Code != http.StatusOK {
		t.Errorf("GET : %d", rec.Code)
	}

	wasm2 := pt.Static(`{"action":"deny","status":451}`)
	if rec := plCall(h, http.MethodPut, "/api/v1/plugins/geo", pluginBody("geo", wasm2)); rec.Code != http.StatusOK {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body.String())
	}
	var sha string
	_ = h.DB.QueryRow(`SELECT sha256 FROM plugins WHERE name='geo'`).Scan(&sha)
	if sum := sha256.Sum256(wasm2); sha != hex.EncodeToString(sum[:]) {
		t.Errorf("module non remplacé : %s", sha)
	}
	if rec := plCall(h, http.MethodPut, "/api/v1/plugins/absent", pluginBody("absent", wasm)); rec.Code != http.StatusNotFound {
		t.Errorf("PUT inconnu : %d", rec.Code)
	}
	if rec := plCall(h, http.MethodDelete, "/api/v1/plugins/geo", nil); rec.Code != http.StatusNoContent {
		t.Errorf("DELETE : %d", rec.Code)
	}
	if rec := plCall(h, http.MethodDelete, "/api/v1/plugins/geo", nil); rec.Code != http.StatusNotFound {
		t.Errorf("DELETE répété : %d", rec.Code)
	}
	// Chaque changement est poussé aux passerelles (POST, PUT, DELETE).
	deadline := time.Now().Add(2 * time.Second)
	for pusher.n.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if n := pusher.n.Load(); n != 3 {
		t.Errorf("envois = %d (attendu 3)", n)
	}
}

// Un module qu'une passerelle refuserait n'est jamais stocké.
func TestPlugins_InstallRefusals(t *testing.T) {
	h, _ := newPluginsHandler(t)
	good := pt.Static(`{}`)

	wrongSHA := pluginBody("a", good)
	wrongSHA["sha256"] = "00"
	noSHA := pluginBody("b", good)
	delete(noSHA, "sha256")
	notWasm := pluginBody("c", []byte("pas du wasm"))
	badName := pluginBody("Bad Name", good)
	noHook := pluginBody("d", good)
	noHook["manifest"] = map[string]any{"name": "d", "version": "1", "api_version": 1, "hooks": []string{}}
	missingHook := pluginBody("e", pt.Loop()) // exporte on_request seulement
	missingHook["manifest"] = map[string]any{"name": "e", "version": "1", "api_version": 1, "hooks": []string{"request", "response"}}
	empty := pluginBody("f", good)
	delete(empty, "wasm")
	huge := pluginBody("g", append(append([]byte{}, good...), make([]byte, maxPluginWasmBytes)...))

	for name, body := range map[string]map[string]any{
		"empreinte fausse": wrongSHA, "sans empreinte": noSHA, "pas du wasm": notWasm, "nom": badName,
		"sans hook": noHook, "hook non exporté": missingHook, "sans module": empty, "trop gros": huge,
	} {
		if rec := plCall(h, http.MethodPost, "/api/v1/plugins", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : %d (attendu 400) %s", name, rec.Code, rec.Body.String())
		}
	}
	// Le nom de l'URL doit être celui du manifeste.
	if rec := plCall(h, http.MethodPut, "/api/v1/plugins/x", pluginBody("y", good)); rec.Code != http.StatusBadRequest {
		t.Errorf("nom incohérent : %d", rec.Code)
	}
	var n int
	_ = h.DB.QueryRow(`SELECT COUNT(1) FROM plugins`).Scan(&n)
	if n != 0 {
		t.Errorf("%d plugin(s) stocké(s) malgré les refus", n)
	}
}

func signedBody(t *testing.T, priv ed25519.PrivateKey, name string, wasm []byte) map[string]any {
	t.Helper()
	body := pluginBody(name, wasm)
	m := plugins.Manifest{Name: name, Version: "1.0.0", APIVersion: 1, Hooks: []string{"request"}}
	sig, err := plugins.Sign(priv, m, body["sha256"].(string))
	if err != nil {
		t.Fatal(err)
	}
	body["signature"] = sig
	return body
}

func addKey(t *testing.T, h *PluginsHandler, pub ed25519.PublicKey) *httptest.ResponseRecorder {
	t.Helper()
	keys := &PluginKeysHandler{DB: h.DB, Log: h.Log}
	var buf bytes.Buffer
	_ = json.NewEncoder(&buf).Encode(map[string]string{"name": "éditeur", "public_key": base64.StdEncoding.EncodeToString(pub)})
	rec := httptest.NewRecorder()
	keys.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/plugin-keys", &buf))
	return rec
}

// Sans clé de confiance, la signature est facultative ; avec une clé, elle devient obligatoire et doit
// venir d'une clé approuvée. Une signature qu'on ne peut pas vérifier ne compte jamais.
func TestPlugins_SignaturePolicy(t *testing.T) {
	h, _ := newPluginsHandler(t)
	wasm := pt.Static(`{}`)
	pub, priv, _ := plugins.GenerateKey()
	_, otherPriv, _ := plugins.GenerateKey()

	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", pluginBody("libre", wasm)); rec.Code != http.StatusCreated {
		t.Fatalf("sans clé, non signé : %d %s", rec.Code, rec.Body.String())
	}
	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", signedBody(t, priv, "orphelin", wasm)); rec.Code != http.StatusBadRequest {
		t.Errorf("signature sans clé de confiance : %d (attendu 400)", rec.Code)
	}

	if rec := addKey(t, h, pub); rec.Code != http.StatusCreated {
		t.Fatalf("ajout de clé : %d %s", rec.Code, rec.Body.String())
	}
	if rec := addKey(t, h, pub); rec.Code != http.StatusConflict {
		t.Errorf("clé en double : %d", rec.Code)
	}
	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", pluginBody("nu", wasm)); rec.Code != http.StatusBadRequest {
		t.Errorf("non signé avec clés configurées : %d (attendu 400)", rec.Code)
	}
	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", signedBody(t, otherPriv, "etranger", wasm)); rec.Code != http.StatusBadRequest {
		t.Errorf("clé non approuvée : %d (attendu 400)", rec.Code)
	}
	tampered := signedBody(t, priv, "falsifie", wasm)
	tampered["manifest"].(map[string]any)["on_error"] = "allow" // manifeste plus permissif que le signé
	if rec := plCall(h, http.MethodPost, "/api/v1/plugins", tampered); rec.Code != http.StatusBadRequest {
		t.Errorf("manifeste modifié : %d (attendu 400)", rec.Code)
	}
	rec := plCall(h, http.MethodPost, "/api/v1/plugins", signedBody(t, priv, "signe", wasm))
	if rec.Code != http.StatusCreated {
		t.Fatalf("signé par une clé de confiance : %d %s", rec.Code, rec.Body.String())
	}
	var info PluginInfo
	_ = json.Unmarshal(rec.Body.Bytes(), &info)
	if info.SignedBy != plugins.KeyID(pub) {
		t.Errorf("signed_by = %q", info.SignedBy)
	}
	// Le remplacement d'un plugin déjà installé est soumis à la même règle.
	if rec := plCall(h, http.MethodPut, "/api/v1/plugins/libre", pluginBody("libre", pt.Static(`{"action":"deny"}`))); rec.Code != http.StatusBadRequest {
		t.Errorf("remplacement non signé : %d (attendu 400)", rec.Code)
	}
}
