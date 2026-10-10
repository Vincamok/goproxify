// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package rulesengine

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
)

// Actions fournies sous forme de modules, avec secret : leurs paramètres vivent sous « params ».

const pagerDutyDefaultURL = "https://events.pagerduty.com/v2/enqueue"

func param(a Action, key string) string {
	s, _ := a.Params[key].(string)
	return strings.TrimSpace(s)
}

func checkHTTPURL(what, raw string) error {
	u, err := url.Parse(strings.TrimSpace(raw))
	if err != nil || u.Host == "" || (u.Scheme != "http" && u.Scheme != "https") {
		return fmt.Errorf("%s : %q n'est pas une URL http(s)", what, raw)
	}
	return nil
}

func paramsOf(cfg map[string]any) map[string]any {
	p, _ := cfg["params"].(map[string]any)
	return p
}

// registerModuleActions déclare les actions à secret. Appelée en fin d'init de action_registry.go : l'ordre des
// init() de plusieurs fichiers dépend de leur nom, or l'ordre d'enregistrement est l'ordre d'affichage.
func registerModuleActions() {
	RegisterAction(modules.Manifest{Type: string(ActionWebhookSigned), Label: "Webhook signé (HMAC-SHA256)",
		Fields: []modules.Field{
			{Key: "params.url", Label: "URL du webhook", Kind: modules.KindText, Required: true},
			{Key: "params.secret", Label: "Secret de signature", Kind: modules.KindPassword, Secret: true, Required: true},
		}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execWebhookSigned(ctx, ac) },
		func(cfg map[string]any) error {
			u, _ := paramsOf(cfg)["url"].(string)
			return checkHTTPURL("params.url", u)
		})

	RegisterAction(modules.Manifest{Type: string(ActionPagerDuty), Label: "PagerDuty (Events API v2)",
		Fields: []modules.Field{
			{Key: "params.routing_key", Label: "Clé d'intégration (routing key)", Kind: modules.KindPassword, Secret: true, Required: true},
			{Key: "params.severity", Label: "Gravité (critical, error, warning, info)", Kind: modules.KindText},
			{Key: "params.url", Label: "URL de l'API (défaut : events.pagerduty.com)", Kind: modules.KindText},
		}},
		func(e *Engine, ctx context.Context, ac ActionContext) error { return e.execPagerDuty(ctx, ac) },
		func(cfg map[string]any) error {
			p := paramsOf(cfg)
			switch sev, _ := p["severity"].(string); strings.TrimSpace(sev) {
			case "", "critical", "error", "warning", "info":
			default:
				return fmt.Errorf("params.severity : %q invalide (critical, error, warning, info)", sev)
			}
			if u, _ := p["url"].(string); strings.TrimSpace(u) != "" {
				return checkHTTPURL("params.url", u)
			}
			return nil
		})
}

func (e *Engine) httpPost(ctx context.Context, rawURL string, body []byte, headers map[string]string, wantStatus func(int) bool, label string) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, rawURL, bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	resp, err := (&http.Client{Timeout: 10 * time.Second, CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }}).Do(req)
	if err != nil {
		return fmt.Errorf("%s: %w", label, err)
	}
	defer resp.Body.Close()
	if !wantStatus(resp.StatusCode) {
		return fmt.Errorf("%s: statut HTTP %d", label, resp.StatusCode)
	}
	return nil
}

func (e *Engine) execWebhookSigned(ctx context.Context, ac ActionContext) error {
	target, secret := param(ac.Rule.Action, "url"), param(ac.Rule.Action, "secret")
	if target == "" || secret == "" {
		return fmt.Errorf("webhook_signed : params.url et params.secret requis")
	}
	body, err := webhookPayload(ac)
	if err != nil {
		return err
	}
	ts := strconv.FormatInt(time.Now().Unix(), 10)
	mac := hmac.New(sha256.New, []byte(secret))
	mac.Write([]byte(ts + "." + string(body)))
	return e.httpPost(ctx, target, body, map[string]string{
		"X-GPX-Timestamp": ts,
		"X-GPX-Signature": "sha256=" + hex.EncodeToString(mac.Sum(nil)),
	}, func(c int) bool { return c < 300 }, "webhook_signed")
}

func (e *Engine) execPagerDuty(ctx context.Context, ac ActionContext) error {
	key := param(ac.Rule.Action, "routing_key")
	if key == "" {
		return fmt.Errorf("pagerduty : params.routing_key requis")
	}
	endpoint := param(ac.Rule.Action, "url")
	if endpoint == "" {
		endpoint = pagerDutyDefaultURL
	}
	severity := param(ac.Rule.Action, "severity")
	if severity == "" {
		severity = "error"
	}
	summary := "[GoProxify] " + ac.Rule.Name
	if ac.Rule.Description != "" {
		summary += " — " + ac.Rule.Description
	}
	dedup := ac.Rule.ID
	if dedup == "" {
		dedup = ac.Rule.Name
	}
	body, err := json.Marshal(map[string]any{
		"routing_key":  key,
		"event_action": "trigger",
		"dedup_key":    dedup,
		"payload": map[string]any{
			"summary":        summary,
			"source":         "goproxify",
			"severity":       severity,
			"custom_details": ac.Detail,
		},
	})
	if err != nil {
		return err
	}
	return e.httpPost(ctx, endpoint, body, nil, func(c int) bool { return c == http.StatusAccepted || c == http.StatusOK }, "pagerduty")
}
