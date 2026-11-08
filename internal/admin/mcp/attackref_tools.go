// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"net/http"
	"net/netip"
	"time"

	"github.com/vincamok/goproxify/internal/admin/attackref"
)

func attackRefTools() []map[string]any {
	return []map[string]any{
		{
			"name": "get_attack_ref_summary",
			"description": "Synthèse du référentiel des attaques (ADR 0023) : nombre de dossiers par profil d'attaquant (scanner, bruteforcer, " +
				"exploiter, enumerator, crawler_abusif), entrées par état et par famille, état du mineur (dernier passage, résultat) et seuils en vigueur.",
			"inputSchema": schema(),
		},
		{
			"name": "list_attack_ref_entries",
			"description": "Entrées du référentiel des attaques : chemins sondés (gabarits) et User-Agent d'outils retenus parce que plusieurs IP " +
				"bannies les ont utilisés et que les visiteurs ne les demandent pas. Chaque entrée porte ses preuves : IP bannies distinctes, jours, " +
				"passages, passages d'IP non bannies (clean_hits), lift (-1 : non mesurable), première/dernière observation. Jamais d'IP ni d'hôte.",
			"inputSchema": schema(
				opt("kind", "string", "path ou ua"),
				opt("family", "string", "config_leak, cms_probe, admin_panel_probe, scanner_generic, sqli, xss, lfi, rce, exploit_cve, offensive_tool…"),
				opt("status", "string", "candidate ou rejected"),
				opt("limit", "number", "Entrées par page (défaut 200, max 1000)"),
				opt("offset", "number", "Décalage de pagination"),
			),
		},
		{
			"name": "list_attack_ref_dossiers",
			"description": "Dossiers par IP bannie : ce que l'IP a fait autour de son ban (gabarits de chemins sondés avec statuts, méthodes, catégories WAF, " +
				"signaux, User-Agent) et son profil (scanner, bruteforcer, exploiter, enumerator, crawler_abusif) avec la raison de chaque profil. " +
				"Les plus récents d'abord ; les IP pseudonymisées ou tronquées (RGPD) n'ont pas de lignes.",
			"inputSchema": schema(
				opt("ip", "string", "Dossiers d'une seule IP"),
				opt("profile", "string", "scanner, bruteforcer, exploiter, enumerator, crawler_abusif, unclassified"),
				opt("days", "number", "Bans des N derniers jours"),
				opt("limit", "number", "Dossiers par page (défaut 100, max 500)"),
				opt("offset", "number", "Décalage de pagination"),
			),
		},
		{
			"name": "set_attack_ref_entry_status",
			"description": "Rejette une entrée du référentiel des attaques (elle n'y reviendra pas au recalcul) ou la remet en candidate.",
			"inputSchema": schema(
				req("kind", "string", "path ou ua"),
				req("value", "string", "Valeur de l'entrée, telle que listée"),
				req("status", "string", "rejected ou candidate"),
			),
		},
		{
			"name": "run_attack_ref_mining",
			"description": "Lance un passage du mineur du référentiel des attaques en arrière-plan : construit les dossiers des bans récents puis recalcule les entrées. " +
				"Sans effet sur le trafic. Répond started=false si un passage tourne déjà.",
			"inputSchema": schema(),
		},
	}
}

func init() { tools = append(tools, attackRefTools()...) }

var errAttackRefUnavailable = errors.New("référentiel des attaques indisponible")

func (h *Handler) attackRefMiner() (*attackref.Miner, error) {
	if h.AttackRef == nil {
		return nil, errAttackRefUnavailable
	}
	return h.AttackRef, nil
}

func (h *Handler) toolAttackRefSummary(r *http.Request) (any, error) {
	m, err := h.attackRefMiner()
	if err != nil {
		return nil, err
	}
	sum, err := m.Store.Summary(r.Context())
	if err != nil {
		return nil, err
	}
	return map[string]any{"summary": sum, "miner": m.Status(), "config": map[string]any{
		"min_ips": m.Cfg.MinIPs, "min_days": m.Cfg.MinDays, "min_lift": m.Cfg.MinLift, "lookback_days": int(m.Cfg.Lookback.Hours() / 24),
	}}, nil
}

func (h *Handler) toolAttackRefEntries(r *http.Request, args map[string]any) (any, error) {
	m, err := h.attackRefMiner()
	if err != nil {
		return nil, err
	}
	es, total, err := m.Store.Entries(r.Context(), attackref.EntryFilter{
		Kind: argStr(args, "kind"), Family: argStr(args, "family"), Status: argStr(args, "status"),
		Limit: argInt(args, "limit", 0), Offset: argInt(args, "offset", 0),
	})
	if err != nil {
		return nil, err
	}
	return map[string]any{"entries": es, "total": total}, nil
}

func (h *Handler) toolAttackRefDossiers(r *http.Request, args map[string]any) (any, error) {
	m, err := h.attackRefMiner()
	if err != nil {
		return nil, err
	}
	f := attackref.DossierFilter{Profile: argStr(args, "profile"), Limit: argInt(args, "limit", 0), Offset: argInt(args, "offset", 0)}
	if ip := argStr(args, "ip"); ip != "" {
		a, err := netip.ParseAddr(ip)
		if err != nil {
			return nil, errors.New("adresse IP invalide")
		}
		f.IP = a.String()
	}
	if days := argInt(args, "days", 0); days > 0 {
		f.Since = time.Now().AddDate(0, 0, -days)
	}
	ds, total, err := m.Store.Dossiers(r.Context(), f)
	if err != nil {
		return nil, err
	}
	return map[string]any{"dossiers": ds, "total": total}, nil
}

func (h *Handler) toolAttackRefSetStatus(r *http.Request, args map[string]any) (any, error) {
	m, err := h.attackRefMiner()
	if err != nil {
		return nil, err
	}
	kind, value, status := argStr(args, "kind"), argStr(args, "value"), argStr(args, "status")
	if err := m.Store.SetStatus(r.Context(), attackref.Kind(kind), value, attackref.Status(status)); err != nil {
		return nil, err
	}
	return map[string]any{"kind": kind, "value": value, "status": status}, nil
}

func (h *Handler) toolAttackRefRun() (any, error) {
	m, err := h.attackRefMiner()
	if err != nil {
		return nil, err
	}
	started := m.Trigger(context.Background())
	return map[string]any{"started": started, "miner": m.Status()}, nil
}
