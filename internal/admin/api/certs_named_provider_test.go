// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

// fakeACME enregistre quelle méthode d'émission l'API a choisie.
type fakeACME struct {
	called chan string
	known  map[string]bool
}

func (f *fakeACME) ObtainCert(_ context.Context, domain string) error {
	f.called <- "default:" + domain
	return nil
}

func (f *fakeACME) ObtainCertWithNamedProvider(_ context.Context, domain, id string) error {
	f.called <- "named:" + id + ":" + domain
	return nil
}

func (f *fakeACME) NamedProviderExists(id string) bool { return f.known[id] }

// plainACME n'implémente pas NamedProviderObtainer.
type plainACME struct{}

func (plainACME) ObtainCert(context.Context, string) error { return nil }

func newCertsHandler(t *testing.T, m CertObtainer) *CertsHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "certs.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &CertsHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil)), Manager: m}
}

func obtainCall(h *CertsHandler, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.obtain(rec, httptest.NewRequest(http.MethodPost, "/api/v1/certs", strings.NewReader(body)))
	return rec
}

func waitCall(t *testing.T, f *fakeACME) string {
	t.Helper()
	select {
	case c := <-f.called:
		return c
	case <-time.After(3 * time.Second):
		t.Fatal("aucune émission déclenchée")
		return ""
	}
}

// Le fournisseur nommé choisi dans « Nouveau certificat » était envoyé (acme_provider_id) mais
// ignoré par le serveur.
func TestObtain_UsesTheNamedProvider(t *testing.T) {
	f := &fakeACME{called: make(chan string, 1), known: map[string]bool{"p1": true}}
	h := newCertsHandler(t, f)
	if rec := obtainCall(h, `{"domain":"*.example.com","acme_provider_id":"p1"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("code %d %s", rec.Code, rec.Body.String())
	}
	if got := waitCall(t, f); got != "named:p1:*.example.com" {
		t.Fatalf("émission = %s", got)
	}
}

func TestObtain_UnknownNamedProviderIsRejectedBeforeStarting(t *testing.T) {
	f := &fakeACME{called: make(chan string, 1), known: map[string]bool{}}
	h := newCertsHandler(t, f)
	if rec := obtainCall(h, `{"domain":"example.com","acme_provider_id":"nope"}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("code %d", rec.Code)
	}
	select {
	case c := <-f.called:
		t.Fatalf("émission déclenchée malgré l'erreur : %s", c)
	case <-time.After(150 * time.Millisecond):
	}
}

func TestObtain_NamedProviderWithoutSupportIs503(t *testing.T) {
	h := newCertsHandler(t, plainACME{})
	if rec := obtainCall(h, `{"domain":"example.com","acme_provider_id":"p1"}`); rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("code %d", rec.Code)
	}
}

func TestObtain_WithoutProviderStillUsesTheDefault(t *testing.T) {
	f := &fakeACME{called: make(chan string, 1)}
	h := newCertsHandler(t, f)
	if rec := obtainCall(h, `{"domain":"example.com"}`); rec.Code != http.StatusAccepted {
		t.Fatalf("code %d", rec.Code)
	}
	if got := waitCall(t, f); got != "default:example.com" {
		t.Fatalf("émission = %s", got)
	}
}
