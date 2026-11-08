// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const attackRefUsage = `Usage: goproxify security attack-ref <sous-commande> [options]

  summary   Dossiers par profil, entrées par état et par famille, état du mineur
  entries   Entrées du référentiel : chemins sondés et User-Agent d'outils retenus, avec leurs preuves
  dossiers  Ce qu'a fait chaque IP bannie autour de son ban, et son profil
  reject    Rejette une entrée (elle ne revient pas au recalcul) : -kind path|ua -value <valeur>
  restore   Remet une entrée rejetée en candidate : -kind path|ua -value <valeur>
  run       Lance un passage du mineur en arrière-plan (sans effet sur le trafic)

goproxify security attack-ref entries  [-kind path|ua] [-family <f>] [-status candidate|rejected] [-limit N] [-offset N] [-json]
goproxify security attack-ref dossiers [-ip <ip>] [-profile <p>] [-days N] [-limit N] [-offset N] [-json]
`

func runSecurityAttackRef() {
	sub := subcommand(os.Args, 3)
	if sub == "" || sub == "help" {
		fmt.Print(attackRefUsage)
		return
	}
	args := parseFlags(os.Args[4:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	const base = "/api/v1/security/attack-ref"
	var (
		method, path string
		body         any
	)
	switch sub {
	case "summary":
		method, path = "GET", base+"/summary"
	case "entries":
		method, path = "GET", base+"/entries?"+attackRefQuery(args, map[string]string{"-kind": "kind", "-family": "family", "-status": "status", "-limit": "limit", "-offset": "offset"})
	case "dossiers":
		method, path = "GET", base+"/dossiers?"+attackRefQuery(args, map[string]string{"-ip": "ip", "-profile": "profile", "-days": "days", "-limit": "limit", "-offset": "offset"})
	case "reject", "restore":
		kind, value := flagValue(args, "-kind", ""), flagValue(args, "-value", "")
		if kind == "" || value == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify security attack-ref %s -kind path|ua -value <valeur>\n", sub)
			os.Exit(1)
		}
		status := "rejected"
		if sub == "restore" {
			status = "candidate"
		}
		method, path, body = "POST", base+"/entries/status", map[string]string{"kind": kind, "value": value, "status": status}
	case "run":
		method, path = "POST", base+"/run"
	default:
		fmt.Fprintf(os.Stderr, "sous-commande inconnue : %s\n\n%s", sub, attackRefUsage)
		os.Exit(1)
	}
	var res map[string]any
	if _, err := client.DoJSON(method, path, body, &res, 202); err != nil {
		fmt.Fprintf(os.Stderr, "attack-ref %s : %v\n", sub, err)
		os.Exit(1)
	}
	if _, ok := args["-json"]; ok {
		out, _ := json.MarshalIndent(res, "", "  ")
		fmt.Println(string(out))
		return
	}
	fmt.Print(formatAttackRef(sub, res))
}

func attackRefQuery(args map[string]string, flags map[string]string) string {
	q := url.Values{}
	for flag, param := range flags {
		if v := flagValue(args, flag, ""); v != "" {
			q.Set(param, v)
		}
	}
	return q.Encode()
}

func formatAttackRef(sub string, res map[string]any) string {
	var sb strings.Builder
	str := func(m map[string]any, k string) string { v, _ := m[k].(string); return v }
	num := func(m map[string]any, k string) float64 { v, _ := m[k].(float64); return v }
	switch sub {
	case "summary":
		sum, _ := res["summary"].(map[string]any)
		fmt.Fprintf(&sb, "%.0f dossiers\n", num(sum, "dossiers"))
		for _, k := range []string{"profiles", "entries_by_status", "entries_by_family"} {
			if m, _ := sum[k].(map[string]any); len(m) > 0 {
				fmt.Fprintf(&sb, "  %s :", k)
				for name, n := range m {
					fmt.Fprintf(&sb, " %s=%.0f", name, n.(float64))
				}
				sb.WriteString("\n")
			}
		}
		if miner, _ := res["miner"].(map[string]any); miner != nil {
			fmt.Fprintf(&sb, "mineur : dernier passage %s\n", orDash(str(miner, "last_run_at")))
		}
	case "entries":
		es, _ := res["entries"].([]any)
		fmt.Fprintf(&sb, "%d entrées sur %.0f\n", len(es), num(res, "total"))
		for _, e := range es {
			m, _ := e.(map[string]any)
			lift := fmt.Sprintf("%.0f", num(m, "lift"))
			if num(m, "lift") < 0 {
				lift = "non mesuré"
			}
			fmt.Fprintf(&sb, "  %-4s %-9s %-18s %s  (%0.f IP, %0.f jours, %0.f passages, lift %s, %s)\n",
				str(m, "kind"), str(m, "status"), str(m, "family"), str(m, "value"), num(m, "distinct_ips"), num(m, "days"), num(m, "hits"), lift, str(m, "last_seen"))
		}
	case "dossiers":
		ds, _ := res["dossiers"].([]any)
		fmt.Fprintf(&sb, "%d dossiers sur %.0f\n", len(ds), num(res, "total"))
		for _, d := range ds {
			m, _ := d.(map[string]any)
			profile := "unclassified"
			if ps, _ := m["profiles"].([]any); len(ps) > 0 {
				profile = str(ps[0].(map[string]any), "profile")
			}
			fmt.Fprintf(&sb, "  %-39s %-14s %s  %0.f requêtes, %0.f chemins\n", str(m, "ip"), profile, str(m, "banned_at"), num(m, "requests"), num(m, "distinct_paths"))
		}
	case "run":
		if started, _ := res["started"].(bool); started {
			sb.WriteString("passage lancé en arrière-plan\n")
		} else {
			sb.WriteString("un passage tourne déjà\n")
		}
	default:
		fmt.Fprintf(&sb, "%s %s : %s\n", sub, str(res, "kind"), str(res, "value"))
		if st := str(res, "status"); st != "" {
			fmt.Fprintf(&sb, "  état : %s\n", st)
		}
	}
	return sb.String()
}
