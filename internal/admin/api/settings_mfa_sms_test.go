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
)

func TestMFASettings_SMSSecretsAreMaskedAndKept(t *testing.T) {
	db, err := admindb.Open(filepath.Join(t.TempDir(), "m.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	h := &MFASettingsHandler{DB: db}
	call := func(method, body string) *httptest.ResponseRecorder {
		rec := httptest.NewRecorder()
		h.ServeHTTP(rec, httptest.NewRequest(method, "/api/v1/settings/mfa/sms", strings.NewReader(body)))
		return rec
	}
	stored := func() string { return admindb.GetSetting(db, "mfa.sms", "") }

	if rec := call(http.MethodPut, `{"provider":"twilio","account_id":"AC1","api_key":"AUTH-TOKEN","api_secret":"S3","from":"+33100","enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("PUT : %d %s", rec.Code, rec.Body.String())
	}
	if out := call(http.MethodGet, "").Body.String(); strings.Contains(out, "AUTH-TOKEN") || strings.Contains(out, "S3") || !strings.Contains(out, "AC1") {
		t.Errorf("GET : %s", out)
	}
	call(http.MethodPut, `{"provider":"twilio","account_id":"AC1","api_key":"••••••••","api_secret":"••••••••","from":"+33200","enabled":true}`)
	if s := stored(); !strings.Contains(s, "AUTH-TOKEN") || !strings.Contains(s, "S3") || !strings.Contains(s, "+33200") {
		t.Errorf("masque renvoyé : %s", s)
	}
	call(http.MethodPut, `{"provider":"twilio","account_id":"AC1","from":"+33300","enabled":true}`)
	if s := stored(); !strings.Contains(s, "AUTH-TOKEN") || !strings.Contains(s, "S3") || !strings.Contains(s, "+33300") {
		t.Errorf("secrets omis effacés : %s", s)
	}
	call(http.MethodPut, `{"provider":"twilio","account_id":"AC1","api_key":"NEW-TOKEN","from":"+33300","enabled":true}`)
	if s := stored(); !strings.Contains(s, "NEW-TOKEN") || !strings.Contains(s, "S3") {
		t.Errorf("secret retapé : %s", s)
	}
}
