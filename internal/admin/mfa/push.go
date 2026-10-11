// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mfa

import (
	"bytes"
	"context"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/ssrf"
)

var ntfyTopic = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Validate refuse une configuration qui ferait envoyer une requête n'importe où : n'importe quel compte peut
// enregistrer un canal push, pas seulement un administrateur. Les adresses privées restent permises (ntfy et
// Gotify s'auto-hébergent) ; le lien local et les métadonnées du cloud ne le sont jamais, y compris à la connexion.
func (c PushConfig) Validate() error {
	switch c.Provider {
	case "ntfy":
		if !ntfyTopic.MatchString(c.Topic) {
			return fmt.Errorf("push: topic invalide (lettres, chiffres, - et _, 64 caractères au plus)")
		}
		if c.URL == "" {
			return nil
		}
	case "gotify":
		if c.URL == "" {
			return fmt.Errorf("push: url requise pour gotify")
		}
	default:
		return fmt.Errorf("push: provider inconnu %q", c.Provider)
	}
	return ssrf.ValidateHTTPURL(c.URL, true)
}

// PushConfig est la configuration d'un canal push pour la 2FA.
type PushConfig struct {
	Provider string `json:"provider"` // ntfy | gotify
	URL      string `json:"url"`
	Topic    string `json:"topic"`    // ntfy seulement
	Token    string `json:"token"`
}

// SendPushMFA envoie une notification push demandant l'approbation de connexion.
func SendPushMFA(ctx context.Context, cfg PushConfig, code, userAgent, ip string) error {
	if err := cfg.Validate(); err != nil {
		return err
	}
	msg := fmt.Sprintf("Code de connexion : %s\n\nIP : %s\nNavigateur : %s\n\nCe code expire dans 5 minutes.",
		code, ip, userAgent)
	switch cfg.Provider {
	case "ntfy":
		return sendNtfyMFA(ctx, cfg, "Connexion Goproxify", msg)
	case "gotify":
		return sendGotifyMFA(ctx, cfg, "Connexion Goproxify", msg)
	default:
		return fmt.Errorf("push: provider inconnu %q", cfg.Provider)
	}
}

func sendNtfyMFA(ctx context.Context, cfg PushConfig, title, body string) error {
	base := strings.TrimRight(cfg.URL, "/")
	if base == "" {
		base = "https://ntfy.sh"
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/"+cfg.Topic, bytes.NewBufferString(body))
	if err != nil {
		return err
	}
	req.Header.Set("Title", title)
	req.Header.Set("Priority", "high")
	req.Header.Set("Tags", "lock")
	if cfg.Token != "" {
		req.Header.Set("Authorization", "Bearer "+cfg.Token)
	}
	resp, err := ssrf.SelfHostedClient(10 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("ntfy push: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("ntfy push: statut %d", resp.StatusCode)
	}
	return nil
}

func sendGotifyMFA(ctx context.Context, cfg PushConfig, title, body string) error {
	base := strings.TrimRight(cfg.URL, "/")
	payload := fmt.Sprintf(`{"title":%q,"message":%q,"priority":8}`, title, body)
	req, err := http.NewRequestWithContext(ctx, http.MethodPost,
		base+"/message", bytes.NewBufferString(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-Gotify-Key", cfg.Token)
	resp, err := ssrf.SelfHostedClient(10 * time.Second).Do(req)
	if err != nil {
		return fmt.Errorf("gotify push: %w", err)
	}
	resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("gotify push: statut %d", resp.StatusCode)
	}
	return nil
}
