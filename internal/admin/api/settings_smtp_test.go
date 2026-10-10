// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/mailer"
)

func TestSMTPSettings_PasswordIsMaskedKeptAndExplicitlyClearable(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "s.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &SMTPSettingsHandler{DB: db}
	put := func(body string) {
		t.Helper()
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(http.MethodPut, "/api/v1/settings/smtp", strings.NewReader(body)))
		if rec.Code != http.StatusOK {
			t.Fatalf("PUT : %d %s", rec.Code, rec.Body.String())
		}
		if strings.Contains(rec.Body.String(), "SMTP-PW") {
			t.Errorf("la réponse renvoie le mot de passe : %s", rec.Body.String())
		}
	}
	const base = `"host":"smtp.x.fr","port":587,"username":"u","from":"a@x.fr"`

	put(`{` + base + `,"password":"SMTP-PW"}`)
	put(`{` + base + `,"password":"••••••••"}`)
	if got := mailer.Load(db).Password; got != "SMTP-PW" {
		t.Errorf("masque renvoyé : %q", got)
	}
	put(`{"host":"smtp2.x.fr","port":587,"username":"u","from":"a@x.fr"}`)
	if got := mailer.Load(db); got.Password != "SMTP-PW" || got.Host != "smtp2.x.fr" {
		t.Errorf("mot de passe omis : %+v", got)
	}
	put(`{` + base + `,"password":""}`)
	if got := mailer.Load(db).Password; got != "" {
		t.Errorf("chaîne vide explicite : %q (doit effacer)", got)
	}
}
