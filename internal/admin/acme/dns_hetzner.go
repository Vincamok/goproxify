// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

// --- Hetzner ---------------------------------------------------------------

const hetznerDefaultBase = "https://dns.hetzner.com/api/v1"

type hetznerProvider struct {
	apiToken string
	zoneID   string

	// Valeurs nulles par défaut ; les tests injectent les leurs.
	baseURL  string
	client   *http.Client
	zoneName string // nom de la zone, lu une fois (les noms d'enregistrement lui sont relatifs)
}

func newHetznerProvider(p map[string]string) (DNSProvider, error) {
	if p["api_token"] == "" || p["zone_id"] == "" {
		return nil, fmt.Errorf("hetzner: api_token et zone_id requis")
	}
	return &hetznerProvider{apiToken: p["api_token"], zoneID: p["zone_id"]}, nil
}

func (h *hetznerProvider) base() string {
	if h.baseURL != "" {
		return strings.TrimRight(h.baseURL, "/")
	}
	return hetznerDefaultBase
}

func (h *hetznerProvider) call(ctx context.Context, method, path string, body, out any) error {
	var payload []byte
	if body != nil {
		payload, _ = json.Marshal(body)
	}
	req, err := http.NewRequestWithContext(ctx, method, h.base()+path, bytes.NewReader(payload))
	if err != nil {
		return err
	}
	req.Header.Set("Auth-API-Token", h.apiToken)
	req.Header.Set("Content-Type", "application/json")
	resp, err := httpClient(h.client).Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		return fmt.Errorf("hetzner: HTTP %d: %s", resp.StatusCode, bodyText(resp.Body))
	}
	if out != nil {
		return json.NewDecoder(resp.Body).Decode(out)
	}
	return nil
}

// zone retourne le nom de la zone, nécessaire pour exprimer un nom d'enregistrement relatif.
func (h *hetznerProvider) zone(ctx context.Context) (string, error) {
	if h.zoneName != "" {
		return h.zoneName, nil
	}
	var out struct {
		Zone struct {
			Name string `json:"name"`
		} `json:"zone"`
	}
	if err := h.call(ctx, http.MethodGet, "/zones/"+url.PathEscape(h.zoneID), nil, &out); err != nil {
		return "", err
	}
	h.zoneName = out.Zone.Name
	return h.zoneName, nil
}

func (h *hetznerProvider) SetTXTRecord(ctx context.Context, domain, value string) error {
	zone, err := h.zone(ctx)
	if err != nil {
		return err
	}
	return h.call(ctx, http.MethodPost, "/records", map[string]any{
		"zone_id": h.zoneID,
		"type":    "TXT",
		"name":    challengeLabel(domain, zone),
		"value":   value,
		"ttl":     60,
	}, nil)
}

// DeleteTXTRecord supprime les TXT de challenge du nom (liste paginée, puis suppression par
// identifiant). Rien à supprimer n'est pas une erreur.
func (h *hetznerProvider) DeleteTXTRecord(ctx context.Context, domain string) error {
	zone, err := h.zone(ctx)
	if err != nil {
		return err
	}
	name := challengeLabel(domain, zone)
	var ids []string
	for page := 1; ; page++ {
		var out struct {
			Records []struct {
				ID   string `json:"id"`
				Type string `json:"type"`
				Name string `json:"name"`
			} `json:"records"`
			Meta struct {
				Pagination struct {
					LastPage int `json:"last_page"`
				} `json:"pagination"`
			} `json:"meta"`
		}
		q := "?zone_id=" + url.QueryEscape(h.zoneID) + "&per_page=100&page=" + strconv.Itoa(page)
		if err := h.call(ctx, http.MethodGet, "/records"+q, nil, &out); err != nil {
			return err
		}
		for _, r := range out.Records {
			if r.Type == "TXT" && strings.EqualFold(r.Name, name) {
				ids = append(ids, r.ID)
			}
		}
		if page >= out.Meta.Pagination.LastPage || len(out.Records) == 0 {
			break
		}
	}
	for _, id := range ids {
		if err := h.call(ctx, http.MethodDelete, "/records/"+url.PathEscape(id), nil, nil); err != nil {
			return err
		}
	}
	return nil
}
