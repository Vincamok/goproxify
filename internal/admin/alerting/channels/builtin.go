// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package channels

import "github.com/vincamok/goproxify/internal/modules"

// Déclaration des canaux fournis avec GoProxify. L'ordre est celui de l'interface.
func init() {
	text := func(key, label, placeholder string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Placeholder: placeholder, Kind: modules.KindText, Required: required}
	}
	secret := func(key, label string, required bool) modules.Field {
		return modules.Field{Key: key, Label: label, Kind: modules.KindPassword, Secret: true, Required: required}
	}

	Register(modules.Manifest{Type: "email", Label: "Email (SMTP)", Fields: []modules.Field{
		text("host", "SMTP host", "mail.example.fr", true),
		{Key: "port", Label: "SMTP port", Placeholder: "587", Kind: modules.KindNumber},
		text("username", "Username", "user@example.fr", false),
		secret("password", "Password", false),
		text("from", "Sender", "goproxify@example.fr", true),
		{Key: "to", Label: "Recipients (comma-separated)", Placeholder: "ops@example.fr", Kind: modules.KindList, Required: true},
	}}, func(cfg map[string]any) Sender {
		return &EmailSender{
			Host: str(cfg, "host"), Port: intv(cfg, "port", 587),
			Username: str(cfg, "username"), Password: str(cfg, "password"),
			From: str(cfg, "from"), To: strSlice(cfg, "to"),
		}
	})

	Register(modules.Manifest{Type: "webhook", Label: "Webhook", Fields: []modules.Field{
		text("url", "URL", "https://hooks.example.fr/…", true),
		secret("secret", "HMAC-SHA256 secret", false),
	}}, func(cfg map[string]any) Sender {
		return &WebhookSender{URL: str(cfg, "url"), Secret: str(cfg, "secret")}
	})

	Register(modules.Manifest{Type: "ntfy", Label: "ntfy", Fields: []modules.Field{
		text("url", "Server URL", "https://ntfy.sh", false),
		text("topic", "Topic", "goproxify-alerts", true),
		secret("token", "Access token (optional)", false),
	}}, func(cfg map[string]any) Sender {
		return &NtfySender{URL: str(cfg, "url"), Topic: str(cfg, "topic"), Token: str(cfg, "token")}
	})

	Register(modules.Manifest{Type: "gotify", Label: "Gotify", Fields: []modules.Field{
		text("url", "Server URL", "https://gotify.example.fr", true),
		secret("token", "Application token", true),
	}}, func(cfg map[string]any) Sender {
		return &GotifySender{URL: str(cfg, "url"), Token: str(cfg, "token")}
	})

	Register(modules.Manifest{Type: "jira", Label: "Jira", Fields: []modules.Field{
		text("url", "Jira URL", "https://xyz.atlassian.net", true),
		text("username", "Username", "", true),
		secret("token", "API token", true),
		text("project", "Project key", "OPS", true),
		text("issue_type", "Issue type", "Bug", false),
	}}, func(cfg map[string]any) Sender {
		return &JiraSender{
			URL: str(cfg, "url"), Username: str(cfg, "username"), Token: str(cfg, "token"),
			Project: str(cfg, "project"), IssueType: str(cfg, "issue_type"),
		}
	})

	Register(modules.Manifest{Type: "linear", Label: "Linear", Fields: []modules.Field{
		secret("api_key", "API key", true),
		text("team_id", "Team ID", "", true),
	}}, func(cfg map[string]any) Sender {
		return &LinearSender{APIKey: str(cfg, "api_key"), TeamID: str(cfg, "team_id")}
	})

	Register(modules.Manifest{Type: "github", Label: "GitHub Issues", Fields: []modules.Field{
		secret("token", "Personal access token", true),
		text("owner", "Owner", "", true),
		text("repo", "Repository", "", true),
	}}, func(cfg map[string]any) Sender {
		return &GitHubSender{Token: str(cfg, "token"), Owner: str(cfg, "owner"), Repo: str(cfg, "repo")}
	})

	Register(modules.Manifest{Type: "gitlab", Label: "GitLab Issues", Fields: []modules.Field{
		text("url", "GitLab URL", "https://gitlab.com", false),
		secret("token", "Access token", true),
		text("project_id", "Project ID", "", true),
	}}, func(cfg map[string]any) Sender {
		return &GitLabSender{URL: str(cfg, "url"), Token: str(cfg, "token"), ProjectID: str(cfg, "project_id")}
	})

	Register(modules.Manifest{Type: "zammad", Label: "Zammad", Fields: []modules.Field{
		text("url", "Zammad URL", "https://zammad.example.fr", true),
		secret("token", "API token", true),
		text("group_id", "Group ID", "1", false),
	}}, func(cfg map[string]any) Sender {
		return &ZammadSender{URL: str(cfg, "url"), Token: str(cfg, "token"), GroupID: str(cfg, "group_id")}
	})

	Register(modules.Manifest{Type: "glpi", Label: "GLPI", Fields: []modules.Field{
		text("url", "GLPI URL", "https://glpi.example.fr", true),
		secret("app_token", "Application token", true),
		secret("user_token", "User token", true),
	}}, func(cfg map[string]any) Sender {
		return &GLPISender{URL: str(cfg, "url"), AppToken: str(cfg, "app_token"), UserToken: str(cfg, "user_token")}
	})

	Register(modules.Manifest{Type: "slack", Label: "Slack", Fields: []modules.Field{
		secret("webhook_url", "Incoming webhook URL", true),
	}}, func(cfg map[string]any) Sender {
		return &SlackSender{WebhookURL: str(cfg, "webhook_url")}
	})

	Register(modules.Manifest{Type: "teams", Label: "Microsoft Teams", Fields: []modules.Field{
		secret("webhook_url", "Incoming webhook URL", true),
	}}, func(cfg map[string]any) Sender {
		return &TeamsSender{WebhookURL: str(cfg, "webhook_url")}
	})

	Register(modules.Manifest{Type: "telegram", Label: "Telegram", Fields: []modules.Field{
		secret("bot_token", "Bot token", true),
		text("chat_id", "Chat ID", "-1001234567890", true),
	}}, func(cfg map[string]any) Sender {
		return &TelegramSender{BotToken: str(cfg, "bot_token"), ChatID: str(cfg, "chat_id")}
	})

	Register(modules.Manifest{Type: "sms", Label: "SMS (Twilio)", Fields: []modules.Field{
		text("account_sid", "Account SID", "", true),
		secret("auth_token", "Auth token", true),
		text("from", "Sender number", "+15551234567", true),
		text("to", "Recipient number", "+15557654321", true),
	}}, func(cfg map[string]any) Sender {
		return &SMSSender{AccountSID: str(cfg, "account_sid"), AuthToken: str(cfg, "auth_token"), From: str(cfg, "from"), To: str(cfg, "to")}
	})
}
