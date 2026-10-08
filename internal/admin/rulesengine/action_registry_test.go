// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"context"
	"reflect"
	"strings"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

func TestActionRegistry_TypesAndEdgeSet(t *testing.T) {
	var types []string
	for _, m := range ActionManifests() {
		types = append(types, m.Type)
	}
	want := "disable_proxy,ban_ip,notify,enable_strict,webhook_call,run_backup,run_playbook"
	if strings.Join(types, ",") != want {
		t.Fatalf("types = %v", types)
	}
	edge := EdgeActionTypes()
	for _, ty := range []string{"disable_proxy", "ban_ip", "notify", "enable_strict"} {
		if !edge[ty] {
			t.Errorf("%s devrait s'exécuter sur une passerelle", ty)
		}
	}
	for _, ty := range []string{"webhook_call", "run_backup", "run_playbook"} {
		if edge[ty] {
			t.Errorf("%s ne doit pas être poussée aux passerelles", ty)
		}
	}
}

// Chaque champ d'action de la structure Action est déclaré par une action : un champ ajouté à la
// structure sans manifeste serait ignoré à la validation.
func TestActionRegistry_CoversActionFields(t *testing.T) {
	declared := map[string]bool{"type": true}
	for _, m := range ActionManifests() {
		for _, f := range m.Fields {
			declared[f.Key] = true
		}
	}
	for _, key := range actionJSONKeys(t) {
		if !declared[key] {
			t.Errorf("champ d'action %q absent de tous les manifestes", key)
		}
	}
}

func TestAction_Validate(t *testing.T) {
	ok := []Action{
		{Type: ActionDisableProxy},
		{Type: ActionBanIP, BanDuration: "24h", BanReason: "x"},
		{Type: ActionBanIP}, // permanent
		{Type: ActionNotify, NotifySeverity: "critical"},
		{Type: ActionNotify},
		{Type: ActionEnableStrict, StrictDuration: "30m"},
		{Type: ActionWebhookCall, WebhookURL: "https://hooks.example.com/x"},
		{Type: ActionRunBackup, BackupRetention: 7},
		{Type: ActionRunPlaybook, PlaybookID: "pb1"},
	}
	for _, a := range ok {
		if err := a.Validate(); err != nil {
			t.Errorf("%+v refusée : %v", a, err)
		}
	}
	bad := map[string]Action{
		"type inconnu":       {Type: "explode"},
		"type vide":          {},
		"durée illisible":    {Type: ActionBanIP, BanDuration: "une heure"},
		"durée négative":     {Type: ActionBanIP, BanDuration: "-1h"},
		"strict illisible":   {Type: ActionEnableStrict, StrictDuration: "bientôt"},
		"gravité":            {Type: ActionNotify, NotifySeverity: "fatal"},
		"webhook sans URL":   {Type: ActionWebhookCall},
		"webhook non http":   {Type: ActionWebhookCall, WebhookURL: "ftp://x/y"},
		"playbook sans id":   {Type: ActionRunPlaybook},
		"rétention négative": {Type: ActionRunBackup, BackupRetention: -1},
	}
	for name, a := range bad {
		if err := a.Validate(); err == nil {
			t.Errorf("%s : acceptée", name)
		}
	}
}

// Les modèles de règles livrés restent valides.
func TestTemplatesActionsAreValid(t *testing.T) {
	for _, tpl := range Templates() {
		if err := tpl.Action.Validate(); err != nil {
			t.Errorf("modèle %s : %v", tpl.ID, err)
		}
	}
}

func TestExecAction_UsesRegistry(t *testing.T) {
	e := &Engine{}
	err := e.execAction(context.Background(), ActionContext{Rule: Rule{Name: "r", Action: Action{Type: "explode"}}})
	if err == nil || !strings.Contains(err.Error(), "inconnu") {
		t.Fatalf("type inconnu : %v", err)
	}
	// Une action enregistrée est exécutée : notify sans dépendance est un no-op sans erreur.
	if err := e.execAction(context.Background(), ActionContext{Rule: Rule{Name: "r", Action: Action{Type: ActionNotify}}}); err != nil {
		t.Fatalf("notify : %v", err)
	}
	// ban_ip sans dépendance configurée remonte l'erreur de l'exécuteur historique.
	err = e.execAction(context.Background(), ActionContext{Rule: Rule{Action: Action{Type: ActionBanIP}}, Detail: map[string]any{"ip": "203.0.113.1"}})
	if err == nil || !strings.Contains(err.Error(), "CreateBan") {
		t.Fatalf("ban_ip : %v", err)
	}
}

func TestRegisterAction_RefusesSecretFields(t *testing.T) {
	defer func() {
		if recover() == nil {
			t.Fatal("un champ secret aurait dû être refusé")
		}
	}()
	RegisterAction(modules.Manifest{Type: "avec_secret", Label: "x", Fields: []modules.Field{
		{Key: "token", Label: "Jeton", Kind: modules.KindPassword, Secret: true},
	}}, nil, nil)
}

func actionJSONKeys(t *testing.T) []string {
	t.Helper()
	rt := reflect.TypeOf(Action{})
	var keys []string
	for i := 0; i < rt.NumField(); i++ {
		if k := strings.Split(rt.Field(i).Tag.Get("json"), ",")[0]; k != "" && k != "-" {
			keys = append(keys, k)
		}
	}
	return keys
}
