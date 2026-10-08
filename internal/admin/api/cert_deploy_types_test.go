// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package api

import (
	"encoding/json"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/modules"
)

func newDeployHandler(t *testing.T) *CertDeployHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "deploy.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &CertDeployHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func deployCall(h *CertDeployHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func TestDeployTargets_CreateValidates(t *testing.T) {
	h := newDeployHandler(t)
	const url = "/api/v1/certs/c1/deploy-targets"
	for name, body := range map[string]string{
		"type inconnu":     `{"name":"x","type":"carrier-pigeon","config":{}}`,
		"webhook sans URL": `{"name":"x","type":"webhook","config":{}}`,
		"ssh sans script":  `{"name":"x","type":"ssh_exec","config":{"host":"h","user":"u","private_key":"k"}}`,
		"clé inconnue":     `{"name":"x","type":"webhook","config":{"url":"https://h","urll":"typo"}}`,
		"pull_token (non)": `{"name":"x","type":"pull_token","config":{}}`,
	} {
		if rec := deployCall(h, http.MethodPost, url, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : code %d (attendu 400)", name, rec.Code)
		}
	}
	for name, body := range map[string]string{
		"webhook": `{"name":"w","type":"webhook","config":{"url":"https://h/hook","secret":"s"}}`,
		"ssh":     `{"name":"s","type":"ssh_exec","config":{"host":"h","user":"u","private_key":"KEY","script":"true"}}`,
	} {
		if rec := deployCall(h, http.MethodPost, url, body); rec.Code != http.StatusCreated {
			t.Errorf("%s : code %d %s", name, rec.Code, rec.Body.String())
		}
	}
}

// La liste ne masquait que « secret » : la clé privée SSH d'une cible était renvoyée en clair à tout
// compte qui peut lire les certificats.
func TestDeployTargets_ListMasksEverySecret(t *testing.T) {
	h := newDeployHandler(t)
	const url = "/api/v1/certs/c1/deploy-targets"
	deployCall(h, http.MethodPost, url, `{"name":"w","type":"webhook","config":{"url":"https://h/hook","secret":"HMAC-SECRET"}}`)
	deployCall(h, http.MethodPost, url, `{"name":"s","type":"ssh_exec","config":{"host":"10.0.0.1","user":"deploy","private_key":"-----BEGIN OPENSSH PRIVATE KEY-----\nPRIVATE-MATERIAL","script":"true"}}`)

	rec := deployCall(h, http.MethodGet, url, "")
	body := rec.Body.String()
	for _, leaked := range []string{"HMAC-SECRET", "PRIVATE-MATERIAL"} {
		if strings.Contains(body, leaked) {
			t.Errorf("secret %q exposé : %s", leaked, body)
		}
	}
	var list []struct {
		Type   string         `json:"type"`
		Config map[string]any `json:"config"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &list); err != nil || len(list) != 2 {
		t.Fatalf("liste = %v, %v", list, err)
	}
	for _, tg := range list {
		switch tg.Type {
		case "webhook":
			if tg.Config["secret"] != modules.Masque || tg.Config["url"] != "https://h/hook" {
				t.Errorf("webhook = %v", tg.Config)
			}
		case "ssh_exec":
			if tg.Config["private_key"] != modules.Masque || tg.Config["host"] != "10.0.0.1" || tg.Config["script"] != "true" {
				t.Errorf("ssh_exec = %v", tg.Config)
			}
		}
	}
}

// Une ligne dont le type n'est plus connu garde le masquage historique des clés sensibles.
func TestMaskDeployConfig_UnknownTypeFallsBack(t *testing.T) {
	got := maskDeployConfig("retired", map[string]any{"secret": "a", "private_key": "b", "url": "https://h"})
	if got["secret"] != "***" || got["private_key"] != "***" || got["url"] != "https://h" {
		t.Fatalf("masquage = %v", got)
	}
}

func TestCertDeployTypes_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	CertDeployTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/cert-deploy-types", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 2 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
	if got[0].Type != "webhook" || got[1].Type != "ssh_exec" {
		t.Errorf("ordre : %s, %s", got[0].Type, got[1].Type)
	}
	multiline := false
	for _, f := range got[1].Fields {
		multiline = multiline || (f.Key == "private_key" && f.Multiline && f.Secret)
	}
	if !multiline {
		t.Error("private_key doit être secret et multiligne")
	}
	rec = httptest.NewRecorder()
	CertDeployTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/cert-deploy-types", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST : %d", rec.Code)
	}
}

func targetID(t *testing.T, h *CertDeployHandler) string {
	t.Helper()
	var id string
	if err := h.DB.QueryRow(`SELECT id FROM cert_deploy_targets ORDER BY rowid DESC LIMIT 1`).Scan(&id); err != nil {
		t.Fatal(err)
	}
	return id
}

func storedConfig(t *testing.T, h *CertDeployHandler, id string) map[string]any {
	t.Helper()
	var raw string
	_ = h.DB.QueryRow(`SELECT config FROM cert_deploy_targets WHERE id=?`, id).Scan(&raw)
	var cfg map[string]any
	_ = json.Unmarshal([]byte(raw), &cfg)
	return cfg
}

func TestDeployTargets_UpdateKeepsSecretsAndRelearnsFingerprint(t *testing.T) {
	h := newDeployHandler(t)
	deployCall(h, http.MethodPost, "/api/v1/certs/c1/deploy-targets",
		`{"name":"s","type":"ssh_exec","config":{"host":"h","user":"u","private_key":"PRIVATE-KEY","script":"true","host_fingerprint":"SHA256:old"}}`)
	id := targetID(t, h)
	url := "/api/v1/certs/c1/deploy-targets/" + id

	// Le formulaire ne ressaisit pas la clé et vide l'empreinte pour la réapprendre.
	rec := deployCall(h, http.MethodPut, url, `{"name":"s2","config":{"host":"h2","user":"u","script":"reload"},"trigger_on":"manual"}`)
	if rec.Code != http.StatusNoContent {
		t.Fatalf("code %d %s", rec.Code, rec.Body.String())
	}
	cfg := storedConfig(t, h, id)
	if cfg["private_key"] != "PRIVATE-KEY" || cfg["host"] != "h2" || cfg["script"] != "reload" {
		t.Fatalf("config = %v", cfg)
	}
	if _, ok := cfg["host_fingerprint"]; ok {
		t.Fatalf("l'empreinte omise doit disparaître : %v", cfg)
	}
	var name, trig string
	_ = h.DB.QueryRow(`SELECT name, trigger_on FROM cert_deploy_targets WHERE id=?`, id).Scan(&name, &trig)
	if name != "s2" || trig != "manual" {
		t.Fatalf("name=%q trigger=%q", name, trig)
	}

	// Le masque renvoyé par la liste, réinjecté tel quel, n'est jamais stocké.
	deployCall(h, http.MethodPut, url, `{"config":{"host":"h2","user":"u","private_key":"`+modules.Masque+`","script":"reload"}}`)
	if storedConfig(t, h, id)["private_key"] != "PRIVATE-KEY" {
		t.Fatal("le masque a remplacé la clé")
	}

	for name, body := range map[string]string{
		"champ requis vidé": `{"config":{"host":"","user":"u","script":"x"}}`,
		"clé inconnue":      `{"config":{"host":"h","user":"u","script":"x","typo":1}}`,
		"déclenchement":     `{"config":{"host":"h","user":"u","script":"x"},"trigger_on":"jamais"}`,
	} {
		if rec := deployCall(h, http.MethodPut, url, body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : code %d (attendu 400)", name, rec.Code)
		}
	}
	if rec := deployCall(h, http.MethodPut, "/api/v1/certs/c1/deploy-targets/inconnu", `{"config":{}}`); rec.Code != http.StatusNotFound {
		t.Errorf("cible inconnue : %d", rec.Code)
	}
}
