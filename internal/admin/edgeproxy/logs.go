// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgeproxy

import (
	"context"
	"net/http"
	"time"

	"github.com/vincamok/goproxify/internal/edge/logapi"
	"github.com/vincamok/goproxify/internal/ssrf"
)

// NewBulkClient : client des exports de logs. La passerelle prend jusqu'à une minute pour lire 100 000 lignes.
func NewBulkClient() *Client {
	return &Client{HTTP: ssrf.SelfHostedClient(75 * time.Second)}
}

// LogSearch demande une page de lignes à la base de logs de la passerelle.
func (c *Client) LogSearch(ctx context.Context, t Target, p logapi.Params) (*logapi.SearchResponse, error) {
	var out logapi.SearchResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathSearch+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogHistogram demande l'histogramme de la passerelle.
func (c *Client) LogHistogram(ctx context.Context, t Target, p logapi.Params) (*logapi.HistogramResponse, error) {
	var out logapi.HistogramResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathHistogram+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogFacets demande les facettes de la passerelle.
func (c *Client) LogFacets(ctx context.Context, t Target, p logapi.Params) (*logapi.FacetsResponse, error) {
	var out logapi.FacetsResponse
	if err := c.do(ctx, t, http.MethodGet, logapi.PathFacets+"?"+p.Values().Encode(), nil, &out); err != nil {
		return nil, err
	}
	return &out, nil
}

// LogReveal demande l'IP réelle d'une ligne pseudonymisée de la passerelle.
func (c *Client) LogReveal(ctx context.Context, t Target, req logapi.RevealRequest) (*logapi.RevealResponse, error) {
	var out logapi.RevealResponse
	if err := c.do(ctx, t, http.MethodPost, logapi.PathReveal, req, &out); err != nil {
		return nil, err
	}
	return &out, nil
}
