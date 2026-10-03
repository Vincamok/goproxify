// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"fmt"
	"net/http"

	"github.com/vincamok/goproxify/internal/admin/api"
	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	admindb "github.com/vincamok/goproxify/internal/admin/db"
)

func banImportTools() []map[string]any {
	return []map[string]any{{
		"name": "import_security_bans",
		"description": "Importe une liste d'adresses IP et de plages CIDR : crée des bans natifs (ou des entrées de la liste blanche avec target=whitelist) en une fois. " +
			"Formats : texte (une adresse ou un CIDR par ligne, commentaires # et ;, comme les listes publiques FireHOL ou Spamhaus DROP), CSV (colonne ip, " +
			"et reason, domain, expires_at ; le CSV de l'export des bans se réimporte tel quel) ou JSON (tableau de chaînes ou d'objets). " +
			"Chaque entrée est validée comme pour create_security_ban (plage plus large que /16 IPv4 ou /32 IPv6 refusée, plage contenant l'appelant refusée) ; " +
			"les doublons, cibles déjà couvertes par un ban ou la liste blanche et plages privées sont ignorés. Au plus 10 000 entrées et 2 Mo. " +
			"Avec dry_run=true, rien n'est créé : le rapport dit ce qui le serait. Retourne le rapport ligne par ligne (créées, ignorées, rejetées). " +
			"Pousse aux passerelles une seule fois pour tout le lot.",
		"inputSchema": schema(
			req("content", "string", "Contenu de la liste"),
			opt("format", "string", "auto (défaut), text, csv ou json"),
			opt("target", "string", "bans (défaut) ou whitelist"),
			opt("reason", "string", "Motif des bans (ou commentaire des entrées) sans motif propre ; défaut « import »"),
			opt("domain", "string", "Domaine ciblé par les bans sans domaine propre (vide = global)"),
			opt("expires_at", "string", "Expiration RFC3339 des bans sans expiration propre ; omis = permanents"),
			opt("dry_run", "boolean", "true : analyser sans rien créer"),
		),
	}}
}

func init() { tools = append(tools, banImportTools()...) }

func (h *Handler) toolImportSecurityBans(r *http.Request, args map[string]any) (any, error) {
	str := func(k string) string { v, _ := args[k].(string); return v }
	dry, _ := args["dry_run"].(bool)
	reqBody := api.ImportRequest{
		Content: str("content"), Format: str("format"), Target: str("target"),
		Reason: str("reason"), Domain: str("domain"), ExpiresAt: str("expires_at"), DryRun: dry,
	}
	actor := adminauth.ActorFromContext(r.Context())
	res, err := api.ImportBans(r.Context(), h.DB, reqBody, api.RequesterIP(r), actor)
	if err != nil {
		return nil, err
	}
	if res.Created > 0 && !res.DryRun {
		_ = admindb.WriteAudit(h.DB, actor, "import_bans", "bans:"+res.Target,
			fmt.Sprintf("%d créé(s), %d ignoré(s), %d rejeté(s) sur %d", res.Created, res.SkippedCount, res.RejectedCount, res.Total))
		if res.Target == api.ImportTargetWhitelist {
			if h.OnWhitelistChange != nil {
				h.OnWhitelistChange()
			}
		} else if h.OnBansChange != nil {
			h.OnBansChange()
		}
	}
	return res, nil
}
