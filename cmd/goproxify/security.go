// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strconv"
	"strings"
	"time"
)

func runSecurity() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "threat":
		runSecurityThreat()
	case "bans":
		runSecurityBans()
	case "trace":
		runSecurityTrace()
	case "waf":
		runSecurityWAF()
	case "waf-engine":
		runSecurityWAFEngine()
	case "cve":
		runSecurityCVE()
	case "engines":
		runSecurityEngines()
	case "help", "":
		fmt.Print(`Usage: goproxify security <sous-commande> [options]

Sous-commandes :
  threat   Config du moteur Sentinel (threat engine global)
  bans     Gestion des IPs bannies
  trace    Parcours complet d'une IP ou d'un CIDR (requêtes, détections, bans)
  waf      Config WAF d'un proxy
  waf-engine  Interrupteur du WAF d'une passerelle (coupe ou rétablit le WAF de tous ses proxies)
  (règles, planifications et playbooks : goproxify automation)
  cve      SLA de correction des CVE (délai attendu selon la gravité)
  engines  Moteurs globaux (Sentinel, Fail2Ban, CrowdSec, WAF) et leurs champs de configuration

goproxify security threat get  [-edge <id>] [-admin-url …] [-token …]
goproxify security threat set  [-edge <id>] -file <config.json> [-admin-url …] [-token …]
goproxify security threat simulate -file <config.json> [-hours N] [-domain <d>] [-edge <id>]

goproxify security engines [-admin-url …] [-token …]

goproxify security bans list   [-admin-url …] [-token …]
goproxify security bans add    -ip <ip|cidr> [-reason <raison>] [-ttl <durée>] [-scope <passerelle|group:nom>] [-admin-url …] [-token …]
goproxify security bans preview -ip <ip|cidr> [-hours N] [-json] [-admin-url …] [-token …]   # impact d'un ban avant de le créer
goproxify security bans asn lookup|preview|ban|unban|info|refresh [-asn <ASN>] [-q <ASN|IP|nom>] [-ttl …] [-scope …] [-dry-run] [-json]   # bans par ASN
goproxify security bans delete -id <ban-id> [-admin-url …] [-token …]
goproxify security bans whitelist list|add|delete [-ip <ip|cidr>] [-comment <texte>] [-admin-url …] [-token …]   # liste blanche des bans
goproxify security bans import -file <chemin|-> [-format auto|text|csv|json] [-target bans|whitelist] [-reason …] [-domain …] [-ttl …] [-scope <passerelle|group:nom>] [-dry-run] [-json] [-admin-url …] [-token …]

goproxify security trace -target <ip|cidr> [-from <date>] [-to <date>] [-order asc|desc] [-limit N] [-offset N] [-json] [-admin-url …] [-token …]

goproxify security waf get  -proxy <id> [-admin-url …] [-token …]
goproxify security waf set  -proxy <id> -file <config.json> [-admin-url …] [-token …]

goproxify security waf-engine get [-edge <id>] [-admin-url …] [-token …]
goproxify security waf-engine set -enabled <true|false> [-edge <id>] [-admin-url …] [-token …]

goproxify security cve sla get [-admin-url …] [-token …]
goproxify security cve sla set -file <sla.json> [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande security inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify security help")
		os.Exit(1)
	}
}

// ── Threat (Sentinel) ─────────────────────────────────────────────────────────

func runSecurityThreat() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		edgeID := flagValue(args, "-edge", "")
		path := "/api/v1/security/threat-config"
		if edgeID != "" {
			path += "?edge=" + url.QueryEscape(edgeID)
		}
		var cfg json.RawMessage
		if _, err := client.DoJSON("GET", path, nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "threat get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security threat set -file <config.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var cfg json.RawMessage
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		edgeID := flagValue(args, "-edge", "")
		path := "/api/v1/security/threat-config"
		if edgeID != "" {
			path += "?edge=" + url.QueryEscape(edgeID)
		}
		if _, err := client.DoJSON("PUT", path, cfg, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "threat set : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Config Sentinel mise à jour.")

	case "simulate":
		args := parseFlags(os.Args[4:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security threat simulate -file <config.json> [-hours N] [-domain <d>] [-edge <id>]")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var cfg json.RawMessage
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		hours, _ := strconv.Atoi(flagValue(args, "-hours", "1"))
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		path := "/api/v1/security/threat-config/simulate"
		if edgeID := flagValue(args, "-edge", ""); edgeID != "" {
			path += "?edge=" + url.QueryEscape(edgeID)
		}
		body := map[string]any{"config": cfg, "hours": hours, "domain": flagValue(args, "-domain", "")}
		var res json.RawMessage
		if _, err := client.DoJSON("POST", path, body, &res); err != nil {
			fmt.Fprintf(os.Stderr, "threat simulate : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))

	default:
		fmt.Fprintf(os.Stderr, "sous-commande threat inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Bans ──────────────────────────────────────────────────────────────────────

// bansAddPayload construit le corps de POST /security/bans. L'API ne connaît que expires_at :
// -ttl (durée Go ou « 7d ») y est converti par rapport à now.
func bansAddPayload(args map[string]string, now time.Time) (map[string]any, error) {
	payload := map[string]any{"ip": flagValue(args, "-ip", "")}
	if r := flagValue(args, "-reason", ""); r != "" {
		payload["reason"] = r
	}
	if sc := flagValue(args, "-scope", ""); sc != "" {
		payload["target_scope"] = sc
	}
	if ttl := flagValue(args, "-ttl", ""); ttl != "" {
		d, err := parseDurationDays(ttl)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("-ttl invalide %q : durée positive attendue (ex. 30m, 24h, 7d)", ttl)
		}
		payload["expires_at"] = now.Add(d).UTC().Format(time.RFC3339)
	}
	return payload, nil
}

// bansListPath ajoute les filtres -edge, -source et -active (true|false) à la liste des bans.
func bansListPath(args map[string]string) string {
	q := url.Values{}
	for flag, param := range map[string]string{"-edge": "edge", "-source": "source", "-active": "active", "-scope": "scope"} {
		if v := flagValue(args, flag, ""); v != "" {
			q.Set(param, v)
		}
	}
	if len(q) == 0 {
		return "/api/v1/security/bans"
	}
	return "/api/v1/security/bans?" + q.Encode()
}

// bansImportPayload construit le corps de POST /security/bans/import depuis le contenu lu et les
// options. -ttl (durée Go ou « 7d ») devient l'expiration par défaut des bans, comme pour « bans add ».
func bansImportPayload(content string, args map[string]string, now time.Time) (map[string]any, error) {
	payload := map[string]any{"content": content}
	for flag, key := range map[string]string{"-format": "format", "-target": "target", "-reason": "reason", "-domain": "domain", "-scope": "scope"} {
		if v := flagValue(args, flag, ""); v != "" {
			payload[key] = v
		}
	}
	if ttl := flagValue(args, "-ttl", ""); ttl != "" {
		d, err := parseDurationDays(ttl)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("-ttl invalide %q : durée positive attendue (ex. 30m, 24h, 7d)", ttl)
		}
		payload["expires_at"] = now.Add(d).UTC().Format(time.RFC3339)
	}
	if _, ok := args["-dry-run"]; ok {
		payload["dry_run"] = true
	}
	return payload, nil
}

// formatBansImport résume le rapport d'un import pour le terminal.
func formatBansImport(res map[string]any) string {
	num := func(k string) int { v, _ := res[k].(float64); return int(v) }
	var b strings.Builder
	verb := "Créées"
	if dry, _ := res["dry_run"].(bool); dry {
		b.WriteString("Analyse seulement (dry-run) : rien n'a été créé.\n")
		verb = "Seraient créées"
	}
	addrs, _ := res["addresses"].(float64)
	fmt.Fprintf(&b, "Format %v, cible %v : %d entrée(s) lue(s)\n", res["format"], res["target"], num("total"))
	fmt.Fprintf(&b, "%s : %d (%.0f adresse(s))  ·  ignorées : %d  ·  rejetées : %d\n", verb, num("created"), addrs, num("skipped_count"), num("rejected_count"))
	section := func(title, key string) {
		list, _ := res[key].([]any)
		if len(list) == 0 {
			return
		}
		fmt.Fprintf(&b, "%s :\n", title)
		for i, x := range list {
			if i == 20 {
				fmt.Fprintf(&b, "  … %d de plus (voir -json)\n", len(list)-20)
				break
			}
			if m, ok := x.(map[string]any); ok {
				fmt.Fprintf(&b, "  ligne %v  %v  — %v\n", m["line"], m["value"], m["reason"])
			}
		}
	}
	section("Rejetées", "rejected")
	section("Ignorées", "skipped")
	return b.String()
}

// runSecurityBansImport : security bans import -file <chemin|-> [-format …] [-target bans|whitelist]
// [-reason …] [-domain …] [-ttl …] [-dry-run] [-json]
func runSecurityBansImport() {
	args := parseFlags(os.Args[4:])
	file := flagValue(args, "-file", "")
	if file == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify security bans import -file <chemin|-> [-format auto|text|csv|json] [-target bans|whitelist] [-reason …] [-domain …] [-ttl …] [-dry-run] [-json]")
		os.Exit(1)
	}
	var raw []byte
	var err error
	if file == "-" {
		raw, err = io.ReadAll(os.Stdin)
	} else {
		raw, err = os.ReadFile(file)
	}
	if err != nil {
		fmt.Fprintf(os.Stderr, "bans import : lecture de %s : %v\n", file, err)
		os.Exit(1)
	}
	payload, err := bansImportPayload(string(raw), args, time.Now())
	if err != nil {
		fmt.Fprintf(os.Stderr, "bans import : %v\n", err)
		os.Exit(1)
	}
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	var res map[string]any
	if _, err := client.DoJSON("POST", "/api/v1/security/bans/import", payload, &res); err != nil {
		fmt.Fprintf(os.Stderr, "bans import : %v\n", err)
		os.Exit(1)
	}
	if _, ok := args["-json"]; ok {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatBansImport(res))
}

// bansWhitelistPath construit /security/bans/whitelist, avec ?ip= pour un retrait.
func bansWhitelistPath(ip string) string {
	if ip == "" {
		return "/api/v1/security/bans/whitelist"
	}
	return "/api/v1/security/bans/whitelist?" + url.Values{"ip": {ip}}.Encode()
}

// runSecurityBansWhitelist : security bans whitelist list | add -ip … [-comment …] | delete -ip …
func runSecurityBansWhitelist() {
	sub := subcommand(os.Args, 4)
	args := parseFlags(os.Args[5:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	switch sub {
	case "list", "":
		var entries []map[string]any
		if _, err := client.DoJSON("GET", bansWhitelistPath(""), nil, &entries); err != nil {
			fmt.Fprintf(os.Stderr, "bans whitelist list : %v\n", err)
			os.Exit(1)
		}
		if len(entries) == 0 {
			fmt.Println("(liste blanche vide)")
			return
		}
		for _, e := range entries {
			line := fmt.Sprintf("%-40v", e["value"])
			if n, _ := e["bans_exempted"].(float64); n > 0 {
				line += fmt.Sprintf("  %d ban(s) neutralisé(s)", int(n))
			}
			if c, _ := e["comment"].(string); c != "" {
				line += "  — " + c
			}
			fmt.Println(line)
		}

	case "add":
		ip := flagValue(args, "-ip", "")
		if ip == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans whitelist add -ip <ip|cidr> [-comment <texte>]")
			os.Exit(1)
		}
		var res map[string]any
		body := map[string]any{"ip": ip, "comment": flagValue(args, "-comment", "")}
		if _, err := client.DoJSON("POST", bansWhitelistPath(""), body, &res, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "bans whitelist add : %v\n", err)
			os.Exit(1)
		}
		if added, _ := res["added"].(bool); !added {
			fmt.Printf("Déjà couvert par %v : rien à faire.\n", res["covered_by"])
			return
		}
		entry, _ := res["entry"].(map[string]any)
		fmt.Printf("Ajouté à la liste blanche : %v\n", entry["value"])
		if n, _ := entry["bans_exempted"].(float64); n > 0 {
			fmt.Printf("%d ban(s) actif(s) ne s'appliquent plus à ces adresses.\n", int(n))
		}

	case "delete":
		ip := flagValue(args, "-ip", "")
		if ip == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans whitelist delete -ip <ip|cidr>")
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", bansWhitelistPath(ip), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "bans whitelist delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%s retiré de la liste blanche.\n", ip)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande whitelist inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// bansPreviewPath construit GET /security/bans/preview?ip=…&hours=….
func bansPreviewPath(args map[string]string) string {
	q := url.Values{}
	q.Set("ip", flagValue(args, "-ip", ""))
	if h := flagValue(args, "-hours", ""); h != "" {
		q.Set("hours", h)
	}
	return "/api/v1/security/bans/preview?" + q.Encode()
}

// formatBanPreview résume l'aperçu d'impact d'un ban pour le terminal.
func formatBanPreview(res map[string]any) string {
	num := func(k string) int { v, _ := res[k].(float64); return int(v) }
	str := func(k string) string { v, _ := res[k].(string); return v }
	var b strings.Builder
	addrs, _ := res["addresses"].(float64)
	fmt.Fprintf(&b, "Cible        : %s (%s, %.0f adresse(s))\n", str("target"), str("kind"), addrs)
	fmt.Fprintf(&b, "Trafic %dh    : %d requête(s) de %d adresse(s) — %d bloquée(s), %d réussie(s) de %d adresse(s)\n",
		num("hours"), num("requests"), num("ips"), num("blocked"), num("ok_requests"), num("ok_ips"))
	if top, _ := res["top_ips"].([]any); len(top) > 0 {
		var parts []string
		for _, t := range top {
			if m, ok := t.(map[string]any); ok {
				c, _ := m["count"].(float64)
				parts = append(parts, fmt.Sprintf("%v (%d)", m["value"], int(c)))
			}
		}
		fmt.Fprintf(&b, "Principales  : %s\n", strings.Join(parts, ", "))
	}
	if bans, _ := res["existing_bans"].([]any); len(bans) > 0 {
		b.WriteString("Bans actifs qui recoupent la cible :\n")
		for _, x := range bans {
			if m, ok := x.(map[string]any); ok {
				fmt.Fprintf(&b, "  - %v (%v, %v)\n", m["ip"], m["source"], m["relation"])
			}
		}
	}
	if profiles, _ := res["profiles"].([]any); len(profiles) > 0 {
		b.WriteString("Profils IP qui recoupent la cible :\n")
		for _, x := range profiles {
			if m, ok := x.(map[string]any); ok {
				fmt.Fprintf(&b, "  - %v (%v)\n", m["name"], m["mode"])
			}
		}
	}
	if warns, _ := res["warnings"].([]any); len(warns) > 0 {
		b.WriteString("Avertissements :\n")
		for _, w := range warns {
			fmt.Fprintf(&b, "  ! %v\n", w)
		}
	} else {
		b.WriteString("Aucun avertissement.\n")
	}
	return b.String()
}

func bansEdgeSuffix(b map[string]any) string {
	out := ""
	if edge, _ := b["edge_name"].(string); edge != "" {
		out = "  [" + edge + "]"
	}
	if scope, _ := b["target_scope"].(string); scope != "" {
		out += "  → " + scope
	}
	return out
}

func runSecurityBans() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var bans []map[string]any
		if _, err := client.DoJSON("GET", bansListPath(args), nil, &bans); err != nil {
			fmt.Fprintf(os.Stderr, "bans list : %v\n", err)
			os.Exit(1)
		}
		if len(bans) == 0 {
			fmt.Println("(aucun ban)")
			return
		}
		for _, b := range bans {
			id, _ := b["id"].(string)
			ip, _ := b["ip"].(string)
			reason, _ := b["reason"].(string)
			expires, _ := b["expires_at"].(string)
			line := fmt.Sprintf("%-36s  %-20s  %s%s", id, ip, reason, bansEdgeSuffix(b))
			if expires != "" {
				line += "  (exp: " + expires + ")"
			}
			fmt.Println(line)
		}

	case "add":
		args := parseFlags(os.Args[4:])
		ip := flagValue(args, "-ip", "")
		if ip == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans add -ip <ip|cidr> [-reason …] [-ttl …]")
			os.Exit(1)
		}
		payload, err := bansAddPayload(args, time.Now())
		if err != nil {
			fmt.Fprintf(os.Stderr, "bans add : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/security/bans", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "bans add : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		fmt.Printf("Ban créé : %s → %s\n", id, ip)

	case "whitelist":
		runSecurityBansWhitelist()

	case "import":
		runSecurityBansImport()

	case "asn":
		runSecurityBansASN()

	case "preview":
		args := parseFlags(os.Args[4:])
		target := flagValue(args, "-ip", "")
		if target == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans preview -ip <ip|cidr> [-hours N] [-json]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var res map[string]any
		if _, err := client.DoJSON("GET", bansPreviewPath(args), nil, &res); err != nil {
			fmt.Fprintf(os.Stderr, "bans preview : %v\n", err)
			os.Exit(1)
		}
		if _, ok := args["-json"]; ok {
			out, _ := json.MarshalIndent(res, "", "  ")
			fmt.Println(string(out))
			return
		}
		fmt.Print(formatBanPreview(res))

	case "delete":
		args := parseFlags(os.Args[4:])
		id := flagValue(args, "-id", "")
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security bans delete -id <ban-id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/security/bans/"+id, nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "bans delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Ban %s supprimé.\n", id)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande bans inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── WAF (par proxy) ───────────────────────────────────────────────────────────

func runSecurityWAF() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[4:])
		proxyID := flagValue(args, "-proxy", "")
		if proxyID == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security waf get -proxy <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var proxy map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(proxyID), nil, &proxy); err != nil {
			fmt.Fprintf(os.Stderr, "proxy get : %v\n", err)
			os.Exit(1)
		}
		cfg := proxyConfig(proxy)
		wafFields := map[string]any{}
		for _, k := range []string{"waf", "sentinel_whitelist"} {
			if v, ok := cfg[k]; ok {
				wafFields[k] = v
			}
		}
		out, _ := json.MarshalIndent(wafFields, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[4:])
		proxyID := flagValue(args, "-proxy", "")
		file := flagValue(args, "-file", "")
		if proxyID == "" || file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security waf set -proxy <id> -file <config.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var patch map[string]any
		if err := json.Unmarshal(data, &patch); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		// Lire la config existante et merger
		var proxy map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/proxies/"+url.PathEscape(proxyID), nil, &proxy); err != nil {
			fmt.Fprintf(os.Stderr, "proxy get : %v\n", err)
			os.Exit(1)
		}
		cfg := proxyConfig(proxy)
		for k, v := range patch {
			cfg[k] = v
		}
		proxy["config"] = cfg
		if _, err := client.DoJSON("PUT", "/api/v1/proxies/"+url.PathEscape(proxyID), proxy, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "proxy set : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Config WAF/Sentinel du proxy %s mise à jour.\n", proxyID)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande waf inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// proxyConfig extrait la map config d'un proxy (config peut être JSON string ou map).
func proxyConfig(proxy map[string]any) map[string]any {
	switch v := proxy["config"].(type) {
	case map[string]any:
		return v
	case string:
		var m map[string]any
		if json.Unmarshal([]byte(v), &m) == nil {
			return m
		}
	}
	return map[string]any{}
}

// ── CVE : SLA de correction ───────────────────────────────────────────────────

func runSecurityCVE() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "sla":
		runSecurityCVESLA()
	default:
		fmt.Fprintf(os.Stderr, "sous-commande cve inconnue : %q\n", sub)
		os.Exit(1)
	}
}

func runSecurityCVESLA() {
	sub := subcommand(os.Args, 4)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[5:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var cfg json.RawMessage
		if _, err := client.DoJSON("GET", "/api/v1/security/sla-config", nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "cve sla get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))

	case "set":
		args := parseFlags(os.Args[5:])
		file := flagValue(args, "-file", "")
		if file == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify security cve sla set -file <sla.json>")
			os.Exit(1)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture fichier : %v\n", err)
			os.Exit(1)
		}
		var cfg json.RawMessage
		if err := json.Unmarshal(data, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "JSON invalide : %v\n", err)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", "/api/v1/security/sla-config", cfg, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "cve sla set : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("SLA de correction des CVE mis à jour.")

	default:
		fmt.Fprintf(os.Stderr, "sous-commande cve sla inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// ── Moteurs de sécurité (Sentinel, Fail2Ban, CrowdSec) ────────────────────────

// runSecurityWAFEngine lit ou règle l'interrupteur du WAF d'une passerelle (ou de son groupe HA).
func runSecurityWAFEngine() {
	sub := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	path := "/api/v1/security/waf-config"
	if edgeID := flagValue(args, "-edge", ""); edgeID != "" {
		path += "?edge=" + url.QueryEscape(edgeID)
	}
	switch sub {
	case "get", "":
		var cfg json.RawMessage
		if _, err := client.DoJSON("GET", path, nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "waf-engine get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(cfg, "", "  ")
		fmt.Println(string(out))
	case "set":
		enabled, err := strconv.ParseBool(flagValue(args, "-enabled", ""))
		if err != nil {
			fmt.Fprintln(os.Stderr, "usage: goproxify security waf-engine set -enabled <true|false> [-edge <id>]")
			os.Exit(1)
		}
		if _, err := client.DoJSON("PUT", path, map[string]bool{"enabled": enabled}, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "waf-engine set : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("WAF de la passerelle : enabled=%t.\n", enabled)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande waf-engine inconnue : %q\n", sub)
		os.Exit(1)
	}
}

func runSecurityEngines() {
	args := parseFlags(os.Args[3:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	var types []struct {
		Type   string `json:"type"`
		Label  string `json:"label"`
		Fields []struct {
			Key    string `json:"key"`
			Secret bool   `json:"secret"`
		} `json:"fields"`
	}
	if _, err := client.DoJSON("GET", "/api/v1/security/engine-types", nil, &types); err != nil {
		fmt.Fprintf(os.Stderr, "security engines : %v\n", err)
		os.Exit(1)
	}
	for _, ty := range types {
		var fields []string
		for _, f := range ty.Fields {
			n := f.Key
			if f.Secret {
				n += " (secret)"
			}
			fields = append(fields, n)
		}
		fmt.Printf("%s — %s\n  %s\n", ty.Type, ty.Label, strings.Join(fields, ", "))
	}
}
