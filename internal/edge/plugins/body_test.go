// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package plugins

import (
	"bytes"
	"context"
	"encoding/json"
	"strings"
	"testing"

	pt "github.com/vincamok/goproxify/internal/edge/plugins/plugintest"
)

func bodyManifest(hooks ...string) Manifest {
	m := manifest(hooks...)
	return m
}

func TestManifest_BodyHookDefaultsAndGuards(t *testing.T) {
	m := bodyManifest(HookRequestBody)
	if err := m.Normalize(); err != nil || m.Limits.MaxBodyBytes != DefaultMaxBodyBytes || m.OnOversize != OnOversizeDeny {
		t.Fatalf("défauts : %+v %v", m, err)
	}
	for name, mutate := range map[string]func(*Manifest){
		"taille négative":   func(m *Manifest) { m.Limits.MaxBodyBytes = -1 },
		"taille au-delà":    func(m *Manifest) { m.Limits.MaxBodyBytes = MaxBodyBytesCap + 1 },
		"on_oversize":       func(m *Manifest) { m.OnOversize = "ignore" },
		"hook de corps nul": func(m *Manifest) { m.Hooks = []string{HookRequest}; m.Limits.MaxBodyBytes = 10 },
	} {
		bm := bodyManifest(HookRequestBody)
		mutate(&bm)
		if err := bm.Normalize(); err == nil {
			t.Errorf("%s : accepté", name)
		}
	}
	// Un plugin sans hook de corps ni capacité garde exactement le manifeste d'avant : son résumé, donc la
	// signature d'un plugin déjà publié, ne change pas.
	old := manifest()
	if err := old.Normalize(); err != nil {
		t.Fatal(err)
	}
	b, _ := json.Marshal(old)
	for _, key := range []string{"on_oversize", "max_body_bytes", "capabilities"} {
		if strings.Contains(string(b), key) {
			t.Errorf("le manifeste d'un plugin simple contient %q : %s", key, b)
		}
	}
	// Le crochet connect est connu.
	cm := bodyManifest(HookConnect)
	if err := cm.Normalize(); err != nil {
		t.Errorf("hook connect : %v", err)
	}
}

func TestCall_BodyIsDeliveredAsBase64(t *testing.T) {
	log, logged := capturingLogger()
	m := bodyManifest(HookRequestBody)
	m.Limits.MaxBodyBytes = 100 << 10 // dépasse les 64 Kio habituels de l'entrée : le plafond d'E/S suit
	p := loadWith(t, m, pt.Log(), log)
	body := bytes.Repeat([]byte{0x00, 0xff, 'a'}, 25000) // 75 000 octets, octets non UTF-8 compris
	_, err := p.Call(context.Background(), HookRequestBody, RequestBodyInput{RequestInput: RequestInput{Method: "POST", Path: "/up"}, Body: body})
	if err != nil {
		t.Fatalf("Call : %v", err)
	}
	var line struct {
		Message string `json:"message"`
	}
	for _, l := range strings.Split(logged(), "\n") {
		if strings.Contains(l, `"message"`) {
			_ = json.Unmarshal([]byte(l), &line)
		}
	}
	// Le journal du plugin est borné (1 Kio) : on ne vérifie que le début, qui porte la requête et le début du
	// corps encodé ; l'essentiel est que l'appel d'un corps de 75 Kio réussisse malgré le plafond de 64 Kio.
	if !strings.Contains(line.Message, `"method":"POST"`) {
		t.Errorf("entrée reçue = %.200q", line.Message)
	}
	// Au-delà du plafond propre au plugin, l'appel est refusé avant d'être fait.
	tooBig := bytes.Repeat([]byte{1}, 200<<10)
	if _, err := p.Call(context.Background(), HookRequestBody, RequestBodyInput{Body: tooBig}); err == nil {
		t.Error("corps de 200 Kio accepté avec un plafond de 100 Kio")
	}
}

func TestOutput_ReplaceBodyAndConnectRules(t *testing.T) {
	ctx := context.Background()
	replace := `{"action":"modify","replace_body":"aGVsbG8="}` // « hello »
	bm := bodyManifest(HookRequest, HookRequestBody, HookConnect)
	p := loadWith(t, bm, pt.Static(replace), nil)
	out, err := p.Call(ctx, HookRequestBody, RequestBodyInput{})
	if err != nil || out.ReplaceBody == nil || string(*out.ReplaceBody) != "hello" {
		t.Fatalf("hook de corps : %+v %v", out, err)
	}
	if _, err := p.Call(ctx, HookRequest, RequestInput{}); err == nil {
		t.Error("replace_body accepté sur un hook sans corps")
	}
	if _, err := p.Call(ctx, HookConnect, ConnectInput{}); err == nil {
		t.Error("replace_body accepté sur connect")
	}
	notModify := loadWith(t, bodyManifest(HookRequestBody), pt.Static(`{"action":"allow","replace_body":"aGk="}`), nil)
	if _, err := notModify.Call(ctx, HookRequestBody, RequestBodyInput{}); err == nil {
		t.Error("replace_body sans action modify accepté")
	}
	modifyConnect := loadWith(t, bodyManifest(HookConnect), pt.Static(`{"action":"modify"}`), nil)
	if _, err := modifyConnect.Call(ctx, HookConnect, ConnectInput{}); err == nil {
		t.Error("modify accepté pour connect")
	}
	deny := loadWith(t, bodyManifest(HookConnect), pt.Static(`{"action":"deny"}`), nil)
	if out, err := deny.Call(ctx, HookConnect, ConnectInput{ClientIP: "203.0.113.9", Protocol: "tcp"}); err != nil || out.Action != ActionDeny {
		t.Errorf("deny sur connect : %+v %v", out, err)
	}
}
