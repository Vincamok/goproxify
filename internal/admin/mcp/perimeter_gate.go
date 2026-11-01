// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"slices"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/rbac"
)

// perimeterBoundTools lisent des logs, des certificats, des alertes ou des métriques sans filtrer par hôte : un compte
// dont l'accès a un périmètre ne les appelle pas (ADR 0022). Ils restent ouverts aux administrateurs et aux accès sans
// critère ; la lecture REST, elle, filtre par périmètre.
var perimeterBoundTools = []string{
	"list_logs",
	"list_certs", "get_cert_status", "list_cert_deploy_targets",
	"list_alerts", "list_alert_events", "list_alert_rules",
	"get_metrics", "get_proxy_metrics",
	"get_prism_anomalies", "get_prism_geo", "get_prism_tls_fingerprints", "get_prism_slo",
}

// denyPerimeterBound refuse à un compte qui n'a pas la permission de l'outil, ou qui ne l'a que sur un périmètre, un outil
// qui ne sait pas filtrer. "" = autorisé.
func (h *Handler) denyPerimeterBound(ctx context.Context, tool string) string {
	if !slices.Contains(perimeterBoundTools, tool) {
		return ""
	}
	caller, err := rbac.LoadCaller(ctx, h.DB, adminauth.UserIDFromContext(ctx))
	if err != nil || caller.IsAdmin() {
		return ""
	}
	filter := caller.Filter(rbac.ToolPermission(tool))
	if filter.None() {
		return "accès insuffisant: " + rbac.ToolPermission(tool)
	}
	if !filter.All() {
		return "outil réservé aux accès sans périmètre (utiliser l'API REST, qui filtre par périmètre)"
	}
	return ""
}
