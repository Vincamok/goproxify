// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
	"github.com/vincamok/goproxify/internal/admin/asn"
)

func asnTools() []map[string]any {
	return []map[string]any{
		{
			"name": "lookup_asn",
			"description": "Cherche un système autonome (ASN) : par numéro (AS16276 ou 16276), par adresse IP (l'ASN qui l'annonce) ou par nom (OVH, Cloudflare…). " +
				"Retourne pour chaque résultat le numéro, le nom, le pays, le nombre de plages annoncées, d'adresses IPv4 et de plages IPv6, et le nombre de plages " +
				"déjà bannies. Données publiques ip2asn (iptoasn.com), installées sur l'Admin au premier usage.",
			"inputSchema": schema(req("q", "string", "Numéro d'ASN, adresse IP ou nom")),
		},
		{
			"name": "preview_asn_ban",
			"description": "Aperçu de l'impact d'un ban d'ASN avant de le créer, sans rien modifier : plages qui seraient bannies, ignorées (déjà bannies, " +
				"liste blanche, privées) ou rejetées, trafic récent de l'ASN (requêtes, dont celles qui ont réussi et seraient coupées, adresses, pays) " +
				"et avertissements (l'ASN contient l'appelant, plages trop larges, aucune requête récente).",
			"inputSchema": schema(
				req("asn", "string", "Numéro d'ASN (AS16276 ou 16276)"),
				opt("hours", "number", "Période de trafic analysée en heures (défaut 24, max 168)"),
			),
		},
		{
			"name": "ban_asn",
			"description": "Bannit un ASN : crée un ban par plage (CIDR) qu'il annonce, en une opération et un seul envoi aux passerelles. Les plages plus larges " +
				"que /16 (IPv4) sont découpées ; les plages déjà bannies, en liste blanche ou privées sont ignorées ; refusé si l'ASN contient l'adresse de l'appelant. " +
				"Le ban est un instantané des plages annoncées : relancer l'outil ajoute les nouvelles plages. Avec dry_run=true, rien n'est créé. " +
				"Mesurer l'impact avant avec preview_asn_ban.",
			"inputSchema": schema(
				req("asn", "string", "Numéro d'ASN (AS16276 ou 16276)"),
				opt("reason", "string", "Motif ; défaut « AS<numéro> <nom> »"),
				opt("domain", "string", "Domaine ciblé (vide = global)"),
				opt("expires_at", "string", "Expiration RFC3339 ; omis = permanent"),
				opt("scope", "string", "Passerelles qui appliquent les bans : nom d'une passerelle ou group:<nom> ; omis = toutes"),
				opt("dry_run", "boolean", "true : simuler sans rien créer"),
			),
		},
		{
			"name":        "unban_asn",
			"description": "Lève les bans créés pour un ASN (toutes ses plages) sur les passerelles, en un seul envoi. Ne touche pas aux autres bans.",
			"inputSchema": schema(req("asn", "string", "Numéro d'ASN (AS16276 ou 16276)")),
		},
	}
}

func init() { tools = append(tools, asnTools()...) }

func (h *Handler) toolLookupASN(r *http.Request, args map[string]any) (any, error) {
	q, _ := args["q"].(string)
	return api.LookupASN(r.Context(), h.DB, h.ASN, q)
}

func (h *Handler) toolPreviewASNBan(r *http.Request, args map[string]any) (any, error) {
	raw, _ := args["asn"].(string)
	hours := 24
	if v, ok := args["hours"].(float64); ok && v > 0 {
		hours = int(v)
	}
	if hours > 168 {
		hours = 168
	}
	return api.ASNPreview(r.Context(), h.DB, h.ASN, h.Groups, raw, hours, api.RequesterIP(r))
}

func (h *Handler) toolBanASN(r *http.Request, args map[string]any) (any, error) {
	str := func(k string) string { v, _ := args[k].(string); return v }
	dry, _ := args["dry_run"].(bool)
	actor := adminauth.ActorFromContext(r.Context())
	res, err := api.BanASN(r.Context(), h.DB, h.ASN, h.Groups, api.ASNBanRequest{
		ASN: str("asn"), Reason: str("reason"), Domain: str("domain"), ExpiresAt: str("expires_at"), Scope: str("scope"), DryRun: dry,
	}, api.RequesterIP(r), actor)
	if err != nil {
		return nil, err
	}
	if res.Created > 0 && !res.DryRun {
		_ = admindb.WriteAudit(h.DB, actor, "ban_asn", fmt.Sprintf("asn:%d", res.ASN),
			fmt.Sprintf("%s : %d plage(s) bannie(s), %d ignorée(s), %d rejetée(s)", res.Name, res.Created, res.SkippedCount, res.RejectedCount))
		if h.OnBansChange != nil {
			h.OnBansChange()
		}
	}
	return res, nil
}

func (h *Handler) toolUnbanASN(r *http.Request, args map[string]any) (any, error) {
	raw, _ := args["asn"].(string)
	n, ok := asn.ParseASN(raw)
	if !ok {
		return nil, fmt.Errorf("ASN invalide %q : numéro attendu (AS16276 ou 16276)", raw)
	}
	ips, err := api.UnbanASN(r.Context(), h.DB, n)
	if err != nil {
		return nil, err
	}
	if len(ips) > 0 {
		_ = admindb.WriteAudit(h.DB, adminauth.ActorFromContext(r.Context()), "unban_asn", fmt.Sprintf("asn:%d", n), fmt.Sprintf("%d plage(s) débannie(s)", len(ips)))
		if h.OnUnbanMany != nil {
			h.OnUnbanMany(ips)
		} else if h.OnBansChange != nil {
			h.OnBansChange()
		}
	}
	return map[string]any{"asn": n, "removed": len(ips)}, nil
}
