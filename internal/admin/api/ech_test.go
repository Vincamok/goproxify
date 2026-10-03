// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/ech"
)

type fakeECHPusher struct{ n atomic.Int32 }

func (f *fakeECHPusher) PushECHKeys(context.Context) { f.n.Add(1) }

func newECHHandler(t *testing.T) (*ECHHandler, *fakeECHPusher) {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "ech.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	p := &fakeECHPusher{}
	return &ECHHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Pusher: p}, p
}

func echCall(t *testing.T, h *ECHHandler, method, path, body string) (int, map[string]any) {
	t.Helper()
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	var out map[string]any
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return rec.Code, out
}

func TestECH_EnableRotateDelete(t *testing.T) {
	h, _ := newECHHandler(t)

	if code, out := echCall(t, h, http.MethodGet, "/api/v1/ech", ""); code != 200 || out["enabled"] != false {
		t.Fatalf("état initial : %d %v", code, out)
	}
	if code, _ := echCall(t, h, http.MethodPut, "/api/v1/ech", `{"enabled":true,"public_name":"*.bad"}`); code != http.StatusBadRequest {
		t.Fatalf("nom public invalide accepté : %d", code)
	}

	code, out := echCall(t, h, http.MethodPut, "/api/v1/ech", `{"enabled":true,"public_name":"ech.example.com"}`)
	if code != 200 || out["enabled"] != true {
		t.Fatalf("activation : %d %v", code, out)
	}
	first := out["active_config_id"]
	if s, _ := out["config_list_b64"].(string); s == "" {
		t.Fatal("config_list_b64 absente")
	}
	if !strings.HasPrefix(out["https_record"].(string), `ech="`) {
		t.Fatalf("https_record = %v", out["https_record"])
	}
	if w, _ := out["warnings"].([]any); len(w) != 1 {
		t.Fatalf("avertissement certificat attendu : %v", out["warnings"])
	}
	if strings.Contains(h.bodyOf(t), "private") {
		t.Fatal("clé privée exposée")
	}

	// Rotation : l'ancienne clé passe en « retirée » mais reste listée.
	code, out = echCall(t, h, http.MethodPost, "/api/v1/ech/rotate", "")
	if code != 200 || out["active_config_id"] == first {
		t.Fatalf("rotation : %d %v", code, out)
	}
	keys := out["keys"].([]any)
	if len(keys) != 2 {
		t.Fatalf("2 clés attendues, %d", len(keys))
	}
	var retiredID, activeID string
	for _, k := range keys {
		m := k.(map[string]any)
		if m["retired"] == true {
			retiredID = m["id"].(string)
		} else {
			activeID = m["id"].(string)
		}
	}
	if code, _ := echCall(t, h, http.MethodDelete, "/api/v1/ech/keys/"+activeID, ""); code != http.StatusNotFound {
		t.Fatalf("suppression de la clé active : %d", code)
	}
	if code, _ := echCall(t, h, http.MethodDelete, "/api/v1/ech/keys/"+retiredID, ""); code != http.StatusNoContent {
		t.Fatalf("suppression de la clé retirée : %d", code)
	}
}

func (h *ECHHandler) bodyOf(t *testing.T) string {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/ech", nil))
	return rec.Body.String()
}

func TestECH_CertCoverageAndPublicNameChange(t *testing.T) {
	h, pusher := newECHHandler(t)
	if _, err := h.DB.Exec(`INSERT INTO certs (id, domain, issuer, expires_at, cert_pem, key_pem) VALUES ('1','*.example.com','x','2099-01-01 00:00:00','','')`); err != nil {
		t.Fatal(err)
	}
	_, out := echCall(t, h, http.MethodPut, "/api/v1/ech", `{"enabled":true,"public_name":"ech.example.com"}`)
	if w, _ := out["warnings"].([]any); len(w) != 0 {
		t.Fatalf("le wildcard couvre le nom public : %v", w)
	}
	first := out["active_config_id"]

	// Changer le nom public régénère la clé (il est gravé dans la config publiée).
	_, out = echCall(t, h, http.MethodPut, "/api/v1/ech", `{"enabled":true,"public_name":"cover.example.com"}`)
	if out["active_config_id"] == first || len(out["keys"].([]any)) != 2 {
		t.Fatalf("clé non régénérée : %v", out)
	}
	if pusher.n.Load() == 0 {
		t.Fatal("aucun push vers les passerelles")
	}
}

func TestECH_PushSet(t *testing.T) {
	h, _ := newECHHandler(t)
	st := ech.NewStore(h.DB)
	set, _ := st.PushSet()
	if set.Keys == nil || len(set.Keys) != 0 {
		t.Fatalf("désactivé : jeu vide non nil attendu, %v", set.Keys)
	}
	if err := st.Configure(true, "ech.example.com"); err != nil {
		t.Fatal(err)
	}
	st.Rotate("ech.example.com") //nolint:errcheck
	set, _ = st.PushSet()
	if len(set.Keys) != 2 || !set.Keys[0].SendAsRetry || set.Keys[1].SendAsRetry {
		t.Fatalf("jeu = %+v (la seule clé active est renvoyée en réessai)", set.Keys)
	}
	if err := st.Configure(false, ""); err != nil {
		t.Fatal(err)
	}
	if set, _ = st.PushSet(); len(set.Keys) != 0 {
		t.Fatal("ECH désactivé doit pousser un jeu vide")
	}
}
