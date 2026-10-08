// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import (
	"reflect"
	"testing"
)

// Caractérisation de Build : chaque type de canal construit le Sender attendu depuis sa config
// stockée. Ce test a précédé la migration vers le registre de modules et garantit que les
// canaux déjà enregistrés en base continuent de se construire à l'identique.
func TestBuild_AllTypes(t *testing.T) {
	cases := []struct {
		typ  string
		cfg  map[string]any
		want Sender
	}{
		{"email", map[string]any{"host": "mail.example.fr", "port": float64(2525), "username": "u", "password": "p", "from": "a@x.fr", "to": []any{"b@x.fr", "c@x.fr"}},
			&EmailSender{Host: "mail.example.fr", Port: 2525, Username: "u", Password: "p", From: "a@x.fr", To: []string{"b@x.fr", "c@x.fr"}}},
		{"email", map[string]any{"host": "h", "from": "f", "to": []string{"t"}},
			&EmailSender{Host: "h", Port: 587, From: "f", To: []string{"t"}}},
		{"webhook", map[string]any{"url": "https://h/x", "secret": "s"}, &WebhookSender{URL: "https://h/x", Secret: "s"}},
		{"ntfy", map[string]any{"url": "https://ntfy.sh", "topic": "t", "token": "k"}, &NtfySender{URL: "https://ntfy.sh", Topic: "t", Token: "k"}},
		{"gotify", map[string]any{"url": "https://g", "token": "k"}, &GotifySender{URL: "https://g", Token: "k"}},
		{"jira", map[string]any{"url": "https://j", "username": "u", "token": "k", "project": "OPS", "issue_type": "Task"},
			&JiraSender{URL: "https://j", Username: "u", Token: "k", Project: "OPS", IssueType: "Task"}},
		{"linear", map[string]any{"api_key": "k", "team_id": "T"}, &LinearSender{APIKey: "k", TeamID: "T"}},
		{"github", map[string]any{"token": "k", "owner": "o", "repo": "r"}, &GitHubSender{Token: "k", Owner: "o", Repo: "r"}},
		{"gitlab", map[string]any{"url": "https://gl", "token": "k", "project_id": "42"}, &GitLabSender{URL: "https://gl", Token: "k", ProjectID: "42"}},
		{"zammad", map[string]any{"url": "https://z", "token": "k", "group_id": "3"}, &ZammadSender{URL: "https://z", Token: "k", GroupID: "3"}},
		{"glpi", map[string]any{"url": "https://g", "app_token": "a", "user_token": "u"}, &GLPISender{URL: "https://g", AppToken: "a", UserToken: "u"}},
		{"slack", map[string]any{"webhook_url": "https://hooks.slack.com/x"}, &SlackSender{WebhookURL: "https://hooks.slack.com/x"}},
		{"teams", map[string]any{"webhook_url": "https://t/x"}, &TeamsSender{WebhookURL: "https://t/x"}},
		{"telegram", map[string]any{"bot_token": "b", "chat_id": "-100"}, &TelegramSender{BotToken: "b", ChatID: "-100"}},
		{"sms", map[string]any{"account_sid": "s", "auth_token": "a", "from": "+1", "to": "+2"}, &SMSSender{AccountSID: "s", AuthToken: "a", From: "+1", To: "+2"}},
	}
	for _, c := range cases {
		got, err := Build(Channel{Type: c.typ, Config: c.cfg})
		if err != nil {
			t.Errorf("%s : %v", c.typ, err)
			continue
		}
		if !reflect.DeepEqual(got, c.want) {
			t.Errorf("%s : got %#v, want %#v", c.typ, got, c.want)
		}
	}
}

func TestBuild_UnknownType(t *testing.T) {
	if _, err := Build(Channel{Type: "carrier-pigeon"}); err == nil {
		t.Fatal("type inconnu accepté")
	}
}

// Un canal stocké avant la migration peut avoir une config partielle ou vide : Build ne doit pas
// la refuser (la validation ne s'applique qu'à la création / modification).
func TestBuild_ToleratesStoredPartialConfig(t *testing.T) {
	for _, typ := range []string{"email", "webhook", "ntfy", "gotify", "jira", "linear", "github", "gitlab", "zammad", "glpi", "slack", "teams", "telegram", "sms"} {
		if _, err := Build(Channel{Type: typ, Config: nil}); err != nil {
			t.Errorf("%s avec config vide : %v", typ, err)
		}
	}
}
