// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package prismedge

import (
	"context"

	"github.com/vincamok/goproxify/internal/admin/edgeproxy"
	"github.com/vincamok/goproxify/internal/edge/logapi"
)

// GatewayCalibration : le calibrage des valeurs de départ de l'ADR 0020 sur le trafic d'une passerelle. Il n'est pas additionné d'une
// passerelle à l'autre : chacune a son trafic, donc ses propres réglages.
type GatewayCalibration struct {
	NodeID   string `json:"node_id"`
	NodeName string `json:"node_name"`
	logapi.EphorCalibrateResponse
}

// Calibrate demande à chaque passerelle (ou à celle de nodeName) de calibrer les réglages sur ses accès récents.
func (s *Source) Calibrate(ctx context.Context, nodeName string, req logapi.EphorCalibrateRequest) ([]GatewayCalibration, Meta, error) {
	out := []GatewayCalibration{}
	m, err := onGateways(ctx, s, nodeName,
		func(ctx context.Context, c *edgeproxy.Client, t edgeproxy.Target) (*logapi.EphorCalibrateResponse, error) {
			return c.EphorCalibrate(ctx, t, req)
		},
		func(t edgeproxy.Target, r *logapi.EphorCalibrateResponse) {
			out = append(out, GatewayCalibration{NodeID: t.ID, NodeName: t.NodeName, EphorCalibrateResponse: *r})
		})
	return out, m, err
}
