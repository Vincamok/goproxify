// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"reflect"
	"testing"

	"github.com/vincamok/goproxify/internal/modules"
)

// Les 14 types livrés avant la migration vers le registre : aucun ne doit disparaître.
var shippedTypes = []string{"email", "webhook", "ntfy", "gotify", "jira", "linear", "github", "gitlab", "zammad", "glpi", "slack", "teams", "telegram", "sms"}

func TestRegistry_ShippedTypesAreRegistered(t *testing.T) {
	var order []string
	for _, m := range Manifests() {
		order = append(order, m.Type)
	}
	if !reflect.DeepEqual(order, shippedTypes) {
		t.Fatalf("types enregistrés = %v", order)
	}
}

// Tout champ qui porte un identifiant secret doit être marqué Secret. Avant le registre, le
// masquage reposait sur une liste de noms de clés qui oubliait webhook_url (Slack, Teams),
// bot_token (Telegram) et auth_token (Twilio) : ces secrets partaient en clair dans l'API.
func TestRegistry_CredentialFieldsAreSecret(t *testing.T) {
	mustBeSecret := map[string][]string{
		"email": {"password"}, "webhook": {"secret"}, "ntfy": {"token"}, "gotify": {"token"},
		"jira": {"token"}, "linear": {"api_key"}, "github": {"token"}, "gitlab": {"token"},
		"zammad": {"token"}, "glpi": {"app_token", "user_token"},
		"slack": {"webhook_url"}, "teams": {"webhook_url"}, "telegram": {"bot_token"}, "sms": {"auth_token"},
	}
	for typ, keys := range mustBeSecret {
		m, ok := ManifestOf(typ)
		if !ok {
			t.Fatalf("%s absent", typ)
		}
		secrets := map[string]bool{}
		for _, f := range m.Fields {
			if f.Secret {
				secrets[f.Key] = true
			}
		}
		for _, k := range keys {
			if !secrets[k] {
				t.Errorf("%s.%s doit être secret", typ, k)
			}
		}
		if len(secrets) != len(keys) {
			t.Errorf("%s : secrets = %v, attendu %v", typ, secrets, keys)
		}
	}
}

// Une configuration complète produite par le formulaire doit passer la validation.
func TestRegistry_ValidateAcceptsFormConfigs(t *testing.T) {
	valid := map[string]map[string]any{
		"email":    {"host": "h", "port": 587, "from": "f", "to": []any{"t"}},
		"webhook":  {"url": "https://h"},
		"ntfy":     {"topic": "t"},
		"gotify":   {"url": "https://g", "token": "k"},
		"jira":     {"url": "https://j", "username": "u", "token": "k", "project": "OPS"},
		"linear":   {"api_key": "k", "team_id": "T"},
		"github":   {"token": "k", "owner": "o", "repo": "r"},
		"gitlab":   {"token": "k", "project_id": "1"},
		"zammad":   {"url": "https://z", "token": "k"},
		"glpi":     {"url": "https://g", "app_token": "a", "user_token": "u"},
		"slack":    {"webhook_url": "https://hooks"},
		"teams":    {"webhook_url": "https://hooks"},
		"telegram": {"bot_token": "b", "chat_id": "1"},
		"sms":      {"account_sid": "s", "auth_token": "a", "from": "+1", "to": "+2"},
	}
	for typ, cfg := range valid {
		m, _ := ManifestOf(typ)
		if err := m.Validate(cfg); err != nil {
			t.Errorf("%s : %v", typ, err)
		}
		if err := m.Validate(map[string]any{}); err == nil && hasRequired(m) {
			t.Errorf("%s : une config vide doit être refusée", typ)
		}
	}
}

func hasRequired(m modules.Manifest) bool {
	for _, f := range m.Fields {
		if f.Required {
			return true
		}
	}
	return false
}

func TestRegistry_OptionalFieldsNotRequired(t *testing.T) {
	// Champs que l'expéditeur complète par une valeur par défaut : ils ne doivent pas être requis.
	optional := map[string][]string{
		"email": {"port", "username", "password"}, "ntfy": {"url", "token"}, "gitlab": {"url"},
		"zammad": {"group_id"}, "jira": {"issue_type"}, "webhook": {"secret"},
	}
	for typ, keys := range optional {
		m, _ := ManifestOf(typ)
		for _, k := range keys {
			for _, f := range m.Fields {
				if f.Key == k && f.Required {
					t.Errorf("%s.%s ne doit pas être requis", typ, k)
				}
			}
		}
	}
}
