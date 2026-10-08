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

func newChannelsHandler(t *testing.T) *ChannelsHandler {
	t.Helper()
	db, err := admindb.Open(filepath.Join(t.TempDir(), "channels.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { db.Close() })
	return &ChannelsHandler{DB: db, Log: slog.New(slog.NewTextHandler(io.Discard, nil))}
}

func chCall(h *ChannelsHandler, method, path, body string) *httptest.ResponseRecorder {
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, httptest.NewRequest(method, path, strings.NewReader(body)))
	return rec
}

func createChannel(t *testing.T, h *ChannelsHandler, body string) string {
	t.Helper()
	rec := chCall(h, http.MethodPost, "/api/v1/alert-channels", body)
	if rec.Code != http.StatusCreated {
		t.Fatalf("création : %d %s", rec.Code, rec.Body.String())
	}
	var out map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &out)
	return out["id"]
}

func listChannels(t *testing.T, h *ChannelsHandler) []map[string]any {
	t.Helper()
	var out []map[string]any
	_ = json.Unmarshal(chCall(h, http.MethodGet, "/api/v1/alert-channels", "").Body.Bytes(), &out)
	return out
}

func TestChannels_CreateValidates(t *testing.T) {
	h := newChannelsHandler(t)
	for name, body := range map[string]string{
		"type inconnu": `{"name":"x","type":"carrier-pigeon","config":{}}`,
		"champ requis": `{"name":"x","type":"slack","config":{}}`,
		"requis vide":  `{"name":"x","type":"gotify","config":{"url":"https://g","token":" "}}`,
		"clé inconnue": `{"name":"x","type":"slack","config":{"webhook_url":"https://h","webhok":"typo"}}`,
		"sans nom":     `{"type":"slack","config":{"webhook_url":"https://h"}}`,
	} {
		if rec := chCall(h, http.MethodPost, "/api/v1/alert-channels", body); rec.Code != http.StatusBadRequest {
			t.Errorf("%s : code %d (attendu 400)", name, rec.Code)
		}
	}
	createChannel(t, h, `{"name":"ok","type":"slack","config":{"webhook_url":"https://hooks.slack.com/services/T/B/secret"}}`)
}

// Slack/Teams (webhook_url), Telegram (bot_token) et Twilio (auth_token) étaient renvoyés en clair
// par GET /alert-channels : la liste de clés à masquer ne les connaissait pas.
func TestChannels_ListMasksEverySecret(t *testing.T) {
	h := newChannelsHandler(t)
	createChannel(t, h, `{"name":"s","type":"slack","config":{"webhook_url":"https://hooks.slack.com/services/T/B/secret"}}`)
	createChannel(t, h, `{"name":"t","type":"telegram","config":{"bot_token":"123:abc","chat_id":"-100"}}`)
	createChannel(t, h, `{"name":"m","type":"sms","config":{"account_sid":"AC1","auth_token":"tw-secret","from":"+1","to":"+2"}}`)

	raw := chCall(h, http.MethodGet, "/api/v1/alert-channels", "").Body.String()
	for _, leaked := range []string{"services/T/B/secret", "123:abc", "tw-secret"} {
		if strings.Contains(raw, leaked) {
			t.Errorf("secret %q exposé par la liste", leaked)
		}
	}
	for _, c := range listChannels(t, h) {
		cfg := c["config"].(map[string]any)
		switch c["type"] {
		case "telegram":
			if cfg["bot_token"] != modules.Masque || cfg["chat_id"] != "-100" {
				t.Errorf("telegram : %v", cfg)
			}
		case "sms":
			if cfg["auth_token"] != modules.Masque || cfg["account_sid"] != "AC1" {
				t.Errorf("sms : %v", cfg)
			}
		}
	}
}

// Modifier un canal sans ressaisir ses secrets (le formulaire ne les préremplit pas) ne doit plus
// les effacer.
func TestChannels_UpdateKeepsOmittedSecrets(t *testing.T) {
	h := newChannelsHandler(t)
	id := createChannel(t, h, `{"name":"tg","type":"telegram","config":{"bot_token":"123:abc","chat_id":"-100"}}`)

	if rec := chCall(h, http.MethodPut, "/api/v1/alert-channels/"+id, `{"name":"tg2","config":{"chat_id":"-200"},"enabled":true}`); rec.Code != http.StatusNoContent {
		t.Fatalf("modification : %d %s", rec.Code, rec.Body.String())
	}
	var cfgJSON string
	if err := h.DB.QueryRow(`SELECT config FROM alert_channels WHERE id=?`, id).Scan(&cfgJSON); err != nil {
		t.Fatal(err)
	}
	var cfg map[string]any
	_ = json.Unmarshal([]byte(cfgJSON), &cfg)
	if cfg["bot_token"] != "123:abc" || cfg["chat_id"] != "-200" {
		t.Fatalf("config stockée = %v", cfg)
	}

	// Le masque renvoyé par la liste, réinjecté tel quel, ne doit jamais être stocké.
	chCall(h, http.MethodPut, "/api/v1/alert-channels/"+id, `{"name":"tg2","config":{"bot_token":"`+modules.Masque+`","chat_id":"-200"},"enabled":true}`)
	_ = h.DB.QueryRow(`SELECT config FROM alert_channels WHERE id=?`, id).Scan(&cfgJSON)
	if strings.Contains(cfgJSON, modules.Masque) {
		t.Fatalf("masque stocké : %s", cfgJSON)
	}

	// Un nouveau secret remplace l'ancien.
	chCall(h, http.MethodPut, "/api/v1/alert-channels/"+id, `{"name":"tg2","config":{"bot_token":"999:new","chat_id":"-200"},"enabled":true}`)
	_ = h.DB.QueryRow(`SELECT config FROM alert_channels WHERE id=?`, id).Scan(&cfgJSON)
	if !strings.Contains(cfgJSON, "999:new") {
		t.Fatalf("nouveau secret non enregistré : %s", cfgJSON)
	}
}

func TestChannels_UpdateValidatesAndHandlesMissing(t *testing.T) {
	h := newChannelsHandler(t)
	id := createChannel(t, h, `{"name":"tg","type":"telegram","config":{"bot_token":"b","chat_id":"-100"}}`)
	if rec := chCall(h, http.MethodPut, "/api/v1/alert-channels/"+id, `{"name":"tg","config":{"chat_id":""}}`); rec.Code != http.StatusBadRequest {
		t.Errorf("config sans champ requis acceptée : %d", rec.Code)
	}
	if rec := chCall(h, http.MethodPut, "/api/v1/alert-channels/inconnu", `{"name":"x","config":{}}`); rec.Code != http.StatusNotFound {
		t.Errorf("canal inconnu : %d", rec.Code)
	}
}

// Un canal créé avant la validation, avec une config partielle, reste listé et modifiable.
func TestChannels_LegacyPartialConfigStillListed(t *testing.T) {
	h := newChannelsHandler(t)
	if _, err := h.DB.Exec(`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES ('old','legacy','slack','{}',1)`); err != nil {
		t.Fatal(err)
	}
	if got := listChannels(t, h); len(got) != 1 || got[0]["name"] != "legacy" {
		t.Fatalf("liste = %v", got)
	}
	if _, err := h.DB.Exec(`INSERT INTO alert_channels (id, name, type, config, enabled) VALUES ('odd','odd','retired-type','{"token":"x"}',1)`); err != nil {
		t.Fatal(err)
	}
	for _, c := range listChannels(t, h) {
		if c["type"] == "retired-type" && c["config"].(map[string]any)["token"] != modules.Masque {
			t.Error("type inconnu : repli sur la liste historique de clés secrètes attendu")
		}
	}
}

func TestChannelTypes_Endpoint(t *testing.T) {
	rec := httptest.NewRecorder()
	ChannelTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodGet, "/api/v1/alert-channel-types", nil))
	var got []modules.Manifest
	if err := json.Unmarshal(rec.Body.Bytes(), &got); err != nil || len(got) != 14 {
		t.Fatalf("manifestes = %d, %v", len(got), err)
	}
	if got[0].Type != "email" || got[len(got)-1].Type != "sms" {
		t.Errorf("ordre : %s … %s", got[0].Type, got[len(got)-1].Type)
	}
	for _, m := range got {
		if m.Label == "" || len(m.Fields) == 0 {
			t.Errorf("manifeste incomplet : %+v", m)
		}
	}
	rec = httptest.NewRecorder()
	ChannelTypesHandler{}.ServeHTTP(rec, httptest.NewRequest(http.MethodPost, "/api/v1/alert-channel-types", nil))
	if rec.Code != http.StatusNotFound {
		t.Errorf("POST : %d", rec.Code)
	}
}
