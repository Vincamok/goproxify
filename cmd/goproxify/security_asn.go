// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
	"time"
)

const asnUsage = `usage: goproxify security bans asn <sous-commande>
  lookup  -q <ASN|IP|nom>                       cherche un ASN
  preview -asn <ASN> [-hours N] [-json]          impact d'un ban d'ASN, sans rien créer
  ban     -asn <ASN> [-reason …] [-domain …] [-ttl …] [-scope <passerelle|group:nom>] [-dry-run] [-json]
  unban   -asn <ASN>                             lève les bans de l'ASN
  info                                           état de la base ASN
  refresh                                        télécharge à nouveau la base ASN`

// asnLookupPath construit GET /security/asn?q=….
func asnLookupPath(q string) string {
	return "/api/v1/security/asn?" + url.Values{"q": {q}}.Encode()
}

// asnPreviewPath construit GET /security/asn/preview?asn=…&hours=….
func asnPreviewPath(args map[string]string) string {
	q := url.Values{"asn": {flagValue(args, "-asn", "")}}
	if h := flagValue(args, "-hours", ""); h != "" {
		q.Set("hours", h)
	}
	return "/api/v1/security/asn/preview?" + q.Encode()
}

// asnBanPayload construit le corps de POST /security/asn/ban ; -ttl (durée Go ou « 7d ») devient une
// expiration par rapport à now.
func asnBanPayload(args map[string]string, now time.Time) (map[string]any, error) {
	p := map[string]any{"asn": flagValue(args, "-asn", "")}
	for flag, key := range map[string]string{"-reason": "reason", "-domain": "domain", "-scope": "scope"} {
		if v := flagValue(args, flag, ""); v != "" {
			p[key] = v
		}
	}
	if ttl := flagValue(args, "-ttl", ""); ttl != "" {
		d, err := parseDurationDays(ttl)
		if err != nil || d <= 0 {
			return nil, fmt.Errorf("-ttl invalide %q : durée positive attendue (ex. 30m, 24h, 7d)", ttl)
		}
		p["expires_at"] = now.Add(d).UTC().Format(time.RFC3339)
	}
	if _, ok := args["-dry-run"]; ok {
		p["dry_run"] = true
	}
	return p, nil
}

func formatASNLookup(list []map[string]any) string {
	if len(list) == 0 {
		return "(aucun ASN trouvé)\n"
	}
	var b strings.Builder
	for _, a := range list {
		n, _ := a["asn"].(float64)
		v4, _ := a["v4_addresses"].(float64)
		ranges, _ := a["ranges"].(float64)
		v6, _ := a["v6_ranges"].(float64)
		banned, _ := a["banned_ranges"].(float64)
		fmt.Fprintf(&b, "AS%.0f  %v (%v)  — %.0f plage(s), %.0f adresse(s) IPv4, %.0f plage(s) IPv6", n, a["name"], a["country"], ranges, v4, v6)
		if banned > 0 {
			fmt.Fprintf(&b, "  [%.0f plage(s) bannie(s)]", banned)
		}
		b.WriteString("\n")
	}
	return b.String()
}

func formatASNPreview(res map[string]any) string {
	num := func(k string) int { v, _ := res[k].(float64); return int(v) }
	info, _ := res["asn"].(map[string]any)
	n, _ := info["asn"].(float64)
	v4, _ := info["v4_addresses"].(float64)
	var b strings.Builder
	fmt.Fprintf(&b, "ASN          : AS%.0f %v (%v) — %.0f adresse(s) IPv4, %v plage(s) IPv6\n", n, info["name"], info["country"], v4, info["v6_ranges"])
	fmt.Fprintf(&b, "Plages       : %d à bannir  ·  ignorées : %d  ·  rejetées : %d  ·  trop larges : %d\n", num("would_create"), num("skipped_count"), num("rejected_count"), num("too_wide"))
	fmt.Fprintf(&b, "Trafic %dh    : %d requête(s) de %d adresse(s) — %d bloquée(s), %d réussie(s) de %d adresse(s)\n",
		num("hours"), num("requests"), num("ips"), num("blocked"), num("ok_requests"), num("ok_ips"))
	if top, _ := res["top_ips"].([]any); len(top) > 0 {
		var parts []string
		for _, x := range top {
			if m, ok := x.(map[string]any); ok {
				parts = append(parts, fmt.Sprintf("%v (%v)", m["value"], m["count"]))
			}
		}
		fmt.Fprintf(&b, "Principales  : %s\n", strings.Join(parts, ", "))
	}
	warns, _ := res["warnings"].([]any)
	if len(warns) == 0 {
		b.WriteString("Aucun avertissement.\n")
	}
	for _, w := range warns {
		fmt.Fprintf(&b, "  ! %v\n", w)
	}
	return b.String()
}

func formatASNBan(res map[string]any) string {
	num := func(k string) int { v, _ := res[k].(float64); return int(v) }
	n, _ := res["asn"].(float64)
	var b strings.Builder
	verb := "Créées"
	if dry, _ := res["dry_run"].(bool); dry {
		b.WriteString("Simulation (dry-run) : rien n'a été créé.\n")
		verb = "Seraient créées"
	}
	fmt.Fprintf(&b, "AS%.0f %v (%v) : %d plage(s) annoncée(s), %d CIDR\n", n, res["name"], res["country"], num("announced_ranges"), num("prefixes"))
	fmt.Fprintf(&b, "%s : %d  ·  ignorées : %d  ·  rejetées : %d  ·  trop larges : %d\n", verb, num("created"), num("skipped_count"), num("rejected_count"), num("too_wide"))
	return b.String()
}

// runSecurityBansASN : security bans asn lookup|preview|ban|unban|info|refresh
func runSecurityBansASN() {
	sub := subcommand(os.Args, 4)
	args := parseFlags(os.Args[5:])
	if sub == "" {
		fmt.Fprintln(os.Stderr, asnUsage)
		os.Exit(1)
	}
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	fail := func(err error) {
		fmt.Fprintf(os.Stderr, "bans asn %s : %v\n", sub, err)
		os.Exit(1)
	}
	needASN := func() {
		if flagValue(args, "-asn", "") == "" {
			fmt.Fprintln(os.Stderr, asnUsage)
			os.Exit(1)
		}
	}
	printJSON := func(v any) {
		out, _ := json.MarshalIndent(v, "", "  ")
		fmt.Println(string(out))
	}
	_, asJSON := args["-json"]

	switch sub {
	case "lookup":
		q := flagValue(args, "-q", "")
		if q == "" {
			fmt.Fprintln(os.Stderr, asnUsage)
			os.Exit(1)
		}
		var list []map[string]any
		if _, err := client.DoJSON("GET", asnLookupPath(q), nil, &list); err != nil {
			fail(err)
		}
		if asJSON {
			printJSON(list)
			return
		}
		fmt.Print(formatASNLookup(list))

	case "preview":
		needASN()
		var res map[string]any
		if _, err := client.DoJSON("GET", asnPreviewPath(args), nil, &res); err != nil {
			fail(err)
		}
		if asJSON {
			printJSON(res)
			return
		}
		fmt.Print(formatASNPreview(res))

	case "ban":
		needASN()
		payload, err := asnBanPayload(args, time.Now())
		if err != nil {
			fail(err)
		}
		var res map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/security/asn/ban", payload, &res); err != nil {
			fail(err)
		}
		if asJSON {
			printJSON(res)
			return
		}
		fmt.Print(formatASNBan(res))

	case "unban":
		needASN()
		var res map[string]any
		path := "/api/v1/security/asn/ban?" + url.Values{"asn": {flagValue(args, "-asn", "")}}.Encode()
		if _, err := client.DoJSON("DELETE", path, nil, &res); err != nil {
			fail(err)
		}
		n, _ := res["removed"].(float64)
		fmt.Printf("%.0f plage(s) débannie(s).\n", n)

	case "info", "refresh":
		var res map[string]any
		method, path := "GET", "/api/v1/security/asn/info"
		if sub == "refresh" {
			method, path = "POST", "/api/v1/security/asn/refresh"
		}
		if _, err := client.DoJSON(method, path, nil, &res); err != nil {
			fail(err)
		}
		printJSON(res)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande asn inconnue : %q\n%s\n", sub, asnUsage)
		os.Exit(1)
	}
}
