// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package certdeploy

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/modules"
	"github.com/vincamok/goproxify/internal/ssrf"
)

type webhookPayload struct {
	Domain      string `json:"domain"`
	CertPEM     string `json:"cert_pem"`
	KeyPEM      string `json:"key_pem"`
	ChainPEM    string `json:"chain_pem"`
	Fingerprint string `json:"fingerprint"`
	ExpiresAt   string `json:"expires_at"`
	TriggeredAt string `json:"triggered_at"`
}

func registerWebhook() {
	Register(modules.Manifest{Type: "webhook", Label: "Webhook (signed HTTP POST)", Fields: []modules.Field{
		{Key: "url", Label: "Webhook URL", Placeholder: "https://your-server.example.com/cert-hook", Kind: modules.KindText, Required: true},
		{Key: "secret", Label: "HMAC secret (optional)", Kind: modules.KindPassword, Secret: true},
	}}, newWebhookTarget)
}

type webhookTarget struct {
	url, secret string
	client      *http.Client
}

func newWebhookTarget(cfg map[string]any, d Deps) (Target, error) {
	if str(cfg, "url") == "" {
		return nil, errors.New("config webhook invalide")
	}
	return &webhookTarget{url: str(cfg, "url"), secret: str(cfg, "secret"), client: d.Client}, nil
}

// Deploy envoie le certificat et la clé en JSON, signés en HMAC-SHA256 si un secret est configuré.
func (w *webhookTarget) Deploy(ctx context.Context, b Bundle) (string, string) {
	// La destination est souvent sur le réseau interne : seuls les schémas non HTTP, les adresses
	// link-local et les métadonnées cloud sont refusés (la clé privée part dans le corps).
	if err := ssrf.ValidateHTTPURL(w.url, true); err != nil {
		return "error", "URL refusée: " + err.Error()
	}
	payload := webhookPayload{
		Domain:      b.Domain,
		CertPEM:     b.CertPEM,
		KeyPEM:      b.KeyPEM,
		ChainPEM:    b.CertPEM,
		Fingerprint: certFingerprint([]byte(b.CertPEM)),
		ExpiresAt:   b.ExpiresAt.UTC().Format(time.RFC3339),
		TriggeredAt: time.Now().UTC().Format(time.RFC3339),
	}
	body, _ := json.Marshal(payload)

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, w.url, bytes.NewReader(body))
	if err != nil {
		return "error", "URL invalide: " + err.Error()
	}
	req.Header.Set("Content-Type", "application/json")
	if w.secret != "" {
		mac := hmac.New(sha256.New, []byte(w.secret))
		mac.Write(body)
		req.Header.Set("X-GoProxify-Signature", "sha256="+hex.EncodeToString(mac.Sum(nil)))
	}

	resp, err := w.client.Do(req)
	if err != nil {
		return "error", "requête échouée: " + err.Error()
	}
	defer resp.Body.Close()

	if resp.StatusCode >= 200 && resp.StatusCode < 300 {
		return "ok", fmt.Sprintf("HTTP %d", resp.StatusCode)
	}
	return "error", fmt.Sprintf("HTTP %d", resp.StatusCode)
}
