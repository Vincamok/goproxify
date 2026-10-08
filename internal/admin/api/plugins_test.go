// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
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
