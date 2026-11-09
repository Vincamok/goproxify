// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"net/http"
	"net/url"
)

// DestSourceTestResult : ce que la passerelle a lu chez le fournisseur avec la configuration d'essai.
type DestSourceTestResult struct {
	OK       bool             `json:"ok"`
	Error    string           `json:"error,omitempty"`
	Count    int              `json:"count"`
	Machines []map[string]any `json:"machines,omitempty"`
}

// TestDestSource fait lire une source une fois par la passerelle (ADR 0024) : le fournisseur doit être joignable depuis elle,
// pas depuis l'Admin.
func (c *Client) TestDestSource(ctx context.Context, t Target, typ string, config map[string]any) (*DestSourceTestResult, error) {
	var out DestSourceTestResult
	body := map[string]any{"type": typ, "config": config}
	if err := c.do(ctx, t, http.MethodPost, "/internal/v1/portal/dest-sources/test", body, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// SyncDestSource demande à la passerelle un passage immédiat de la source.
func (c *Client) SyncDestSource(ctx context.Context, t Target, id string) error {
	return c.do(ctx, t, http.MethodPost, "/internal/v1/portal/dest-sources/"+url.PathEscape(id)+"/sync", nil, nil)
}

// PortalLoginPubKey lit la clé publique avec laquelle sceller les secrets des logins préconfigurés du portail (ADR 0025).
func (c *Client) PortalLoginPubKey(ctx context.Context, t Target) (string, error) {
	var out struct {
		PublicKey string `json:"public_key"`
	}
	if err := c.do(ctx, t, http.MethodGet, "/internal/v1/portal/login-pubkey", nil, &out); err != nil {
		return "", err
	}
	return out.PublicKey, nil
}
