// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestImportConfigFormats(t *testing.T) {
	h := &ImportHandler{}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/import/config-formats", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d", rec.Code)
	}
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	var ids []string
	for _, m := range got {
		ids = append(ids, m.Type)
		if m.Label == "" || m.String("hint") == "" {
			t.Errorf("%s : libellé ou indication manquant", m.Type)
		}
	}
	want := "nginx,traefik-yaml,traefik-toml,caddy,haproxy,goproxify,json"
	if strings.Join(ids, ",") != want {
		t.Fatalf("formats = %v, attendu %s", ids, want)
	}
	if !strings.Contains(rec.Body.String(), `"fields":[]`) {
		t.Error("fields doit être [] (et non null) pour un format sans champ")
	}
}

func TestImportConfigFormats_RejectsOtherMethods(t *testing.T) {
	rec := httptest.NewRecorder()
	(&ImportHandler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/import/config-formats", nil))
	if rec.Code != http.StatusNotFound {
		t.Fatalf("POST : %d", rec.Code)
	}
}

// bigBackup fabrique une sauvegarde valide d'environ n octets (un snippet volumineux).
func bigBackup(t *testing.T, n int) []byte {
	t.Helper()
	body, err := json.Marshal(map[string]any{
		"version":  "1",
		"snippets": []map[string]any{{"id": "s1", "name": "gros", "content": strings.Repeat("x", n)}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return body
}

// Une sauvegarde de plus de 32 Mio (l'ancienne borne) est lue en entier : l'aperçu ne la coupe plus.
func TestBackupPreviewAcceptsALargeFile(t *testing.T) {
	body := bigBackup(t, 40<<20)
	rec := httptest.NewRecorder()
	(&ImportHandler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/import/backup/preview", bytes.NewReader(body)))
	if rec.Code != http.StatusOK {
		t.Fatalf("code %d : %.200s", rec.Code, rec.Body.String())
	}
	var sum struct {
		SnippetCount int `json:"snippet_count"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &sum); err != nil || sum.SnippetCount != 1 {
		t.Fatalf("résumé : %+v, %v", sum, err)
	}
}

// Au-delà de la borne, la réponse dit pourquoi (413 et la limite) au lieu de couper la connexion.
func TestBackupPreviewAndApplyAnswer413WithTheLimit(t *testing.T) {
	old := ImportBackupMaxBytes
	ImportBackupMaxBytes = 1 << 20
	defer func() { ImportBackupMaxBytes = old }()
	body := bigBackup(t, 2<<20)

	for name, payload := range map[string][]byte{
		"preview": body,
		"apply":   append(append([]byte(`{"data":`), body...), `,"selection":{}}`...),
	} {
		rec := httptest.NewRecorder()
		(&ImportHandler{}).ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/import/backup/"+name, bytes.NewReader(payload)))
		if rec.Code != http.StatusRequestEntityTooLarge || !strings.Contains(rec.Body.String(), "1 Mio au plus") {
			t.Errorf("%s : %d %s", name, rec.Code, rec.Body.String())
		}
	}
}
