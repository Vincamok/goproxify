// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestModuleActions_AreNotPushedToGateways(t *testing.T) {
	edge := EdgeActionTypes()
	if edge["webhook_signed"] || edge["pagerduty"] {
		t.Fatalf("les actions à secret ne doivent jamais voyager vers une passerelle : %v", edge)
	}
}

func TestModuleActions_Validate(t *testing.T) {
	ok := []Action{
		{Type: ActionWebhookSigned, Params: map[string]any{"url": "https://hooks.example.com/x", "secret": "s"}},
		{Type: ActionPagerDuty, Params: map[string]any{"routing_key": "R"}},
		{Type: ActionPagerDuty, Params: map[string]any{"routing_key": "R", "severity": "critical", "url": "https://events.eu.pagerduty.com/v2/enqueue"}},
	}
	for _, a := range ok {
		if err := a.Validate(); err != nil {
			t.Errorf("%+v refusée : %v", a, err)
		}
	}
	bad := map[string]Action{
		"signé sans secret":  {Type: ActionWebhookSigned, Params: map[string]any{"url": "https://x.example.com"}},
		"signé sans URL":     {Type: ActionWebhookSigned, Params: map[string]any{"secret": "s"}},
		"signé URL ftp":      {Type: ActionWebhookSigned, Params: map[string]any{"url": "ftp://x", "secret": "s"}},
		"signé clé inconnue": {Type: ActionWebhookSigned, Params: map[string]any{"url": "https://x.example.com", "secret": "s", "extra": 1}},
		"pagerduty sans clé": {Type: ActionPagerDuty},
		"pagerduty gravité":  {Type: ActionPagerDuty, Params: map[string]any{"routing_key": "R", "severity": "fatal"}},
		"pagerduty URL":      {Type: ActionPagerDuty, Params: map[string]any{"routing_key": "R", "url": "pas-une-url"}},
	}
	for name, a := range bad {
		if err := a.Validate(); err == nil {
			t.Errorf("%s : acceptée", name)
		}
	}
}

func TestMaskAndKeepActionSecrets(t *testing.T) {
	a := Action{Type: ActionPagerDuty, Params: map[string]any{"routing_key": "SECRET-KEY", "severity": "critical"}}
	b, _ := json.Marshal(MaskAction(a))
	if strings.Contains(string(b), "SECRET-KEY") || !strings.Contains(string(b), modules.Masque) || !strings.Contains(string(b), "critical") {
		t.Fatalf("masquage = %s", b)
	}
	// Renvoyer le masque, ou omettre le secret, conserve la valeur enregistrée.
	for name, next := range map[string]Action{
		"masque renvoyé": {Type: ActionPagerDuty, Params: map[string]any{"routing_key": modules.Masque, "severity": "info"}},
		"secret omis":    {Type: ActionPagerDuty, Params: map[string]any{"severity": "info"}},
	} {
		kept := KeepActionSecrets(a, next)
		if kept.Params["routing_key"] != "SECRET-KEY" || kept.Params["severity"] != "info" {
			t.Errorf("%s : %+v", name, kept.Params)
		}
	}
	// Un secret retapé remplace l'ancien ; un changement de type ne reprend rien.
	if got := KeepActionSecrets(a, Action{Type: ActionPagerDuty, Params: map[string]any{"routing_key": "NOUVEAU"}}); got.Params["routing_key"] != "NOUVEAU" {
		t.Errorf("secret retapé : %+v", got.Params)
	}
	if got := KeepActionSecrets(a, Action{Type: ActionWebhookSigned, Params: map[string]any{"url": "https://x.example.com"}}); got.Params["secret"] != nil {
		t.Errorf("secret d'un autre type repris : %+v", got.Params)
	}
	plain := Action{Type: ActionBanIP, BanDuration: "1h"}
	if MaskAction(plain).BanDuration != "1h" {
		t.Error("une action sans secret doit rester intacte")
	}
}

func TestMaskRawHelpers(t *testing.T) {
	raw := []byte(`{"type":"webhook_signed","params":{"url":"https://x.example.com","secret":"S3CRET"}}`)
	if masked := string(MaskActionRaw(raw)); strings.Contains(masked, "S3CRET") || !strings.Contains(masked, "https://x.example.com") {
		t.Errorf("MaskActionRaw = %s", masked)
	}
	steps := []byte(`[{"type":"wait","wait_sec":5},{"type":"action","action":{"type":"pagerduty","params":{"routing_key":"KEY1"}}}]`)
	masked := string(MaskStepsRaw(steps))
	if strings.Contains(masked, "KEY1") || !strings.Contains(masked, modules.Masque) || !strings.Contains(masked, "wait_sec") {
		t.Errorf("MaskStepsRaw = %s", masked)
	}
	kept := string(KeepStepsSecrets(steps, []byte(`[{"type":"wait","wait_sec":9},{"type":"action","action":{"type":"pagerduty","params":{"routing_key":"`+modules.Masque+`"}}}]`)))
	if !strings.Contains(kept, "KEY1") || !strings.Contains(kept, `"wait_sec":9`) {
		t.Errorf("KeepStepsSecrets = %s", kept)
	}
	// Valeurs illisibles : renvoyées telles quelles, jamais d'échec.
	if string(MaskActionRaw([]byte("pas du json"))) != "pas du json" || string(MaskStepsRaw([]byte("{"))) != "{" {
		t.Error("valeur illisible modifiée")
	}
}

func TestExec_WebhookSignedSignsTheBody(t *testing.T) {
	var gotBody []byte
	var gotHeaders http.Header
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotBody, _ = io.ReadAll(r.Body)
		gotHeaders = r.Header.Clone()
	}))
	defer srv.Close()
	e := &Engine{}
	ac := ActionContext{Rule: Rule{ID: "r1", Name: "Pic de bans", Action: Action{Type: ActionWebhookSigned, Params: map[string]any{"url": srv.URL, "secret": "s3cr3t"}}}, Detail: map[string]any{"ip": "203.0.113.1"}}
	if err := e.execAction(context.Background(), ac); err != nil {
		t.Fatal(err)
	}
	ts := gotHeaders.Get("X-GPX-Timestamp")
	mac := hmac.New(sha256.New, []byte("s3cr3t"))
	mac.Write([]byte(ts + "." + string(gotBody)))
	if want := "sha256=" + hex.EncodeToString(mac.Sum(nil)); gotHeaders.Get("X-GPX-Signature") != want || ts == "" {
		t.Errorf("signature = %q (attendu %q)", gotHeaders.Get("X-GPX-Signature"), want)
	}
	if !strings.Contains(string(gotBody), "Pic de bans") || strings.Contains(string(gotBody), "s3cr3t") {
		t.Errorf("corps = %s (le secret ne doit jamais y figurer)", gotBody)
	}
	failing := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(500) }))
	defer failing.Close()
	ac.Rule.Action.Params["url"] = failing.URL
	if err := e.execAction(context.Background(), ac); err == nil {
		t.Error("une réponse 500 doit faire échouer l'action")
	}
}

func TestExec_PagerDutyPayload(t *testing.T) {
	var got map[string]any
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&got)
		w.WriteHeader(http.StatusAccepted)
	}))
	defer srv.Close()
	e := &Engine{}
	ac := ActionContext{Rule: Rule{ID: "r42", Name: "CrowdSec silencieux", Action: Action{Type: ActionPagerDuty, Params: map[string]any{"routing_key": "KEY", "url": srv.URL, "severity": "critical"}}}, Detail: map[string]any{"engine": "crowdsec"}}
	if err := e.execAction(context.Background(), ac); err != nil {
		t.Fatal(err)
	}
	payload, _ := got["payload"].(map[string]any)
	if got["routing_key"] != "KEY" || got["event_action"] != "trigger" || got["dedup_key"] != "r42" ||
		payload["severity"] != "critical" || payload["source"] != "goproxify" || !strings.Contains(payload["summary"].(string), "CrowdSec silencieux") {
		t.Errorf("charge utile = %+v", got)
	}
	delete(ac.Rule.Action.Params, "severity")
	_ = e.execAction(context.Background(), ac)
	if got["payload"].(map[string]any)["severity"] != "error" {
		t.Errorf("gravité par défaut = %v", got["payload"])
	}
	ac.Rule.Action.Params = map[string]any{"url": srv.URL}
	if err := e.execAction(context.Background(), ac); err == nil {
		t.Error("clé manquante acceptée")
	}
}
