// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strconv"
	"time"
)

func runPrism() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "anomalies", "geo", "tls":
	default:
		fmt.Fprintln(os.Stderr, "usage : goproxify prism anomalies|geo|tls [-hours N] [-edge <nœud>] [-proxy <hôte>] [-level country|city] [-limit N]")
		os.Exit(1)
	}
	args := parseFlags(os.Args[3:])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}

	hours := 24.0
	if v, err := strconv.ParseFloat(flagValue(args, "-hours", "24"), 64); err == nil && v > 0 {
		hours = v
	}
	now := time.Now().UTC()
	q := url.Values{}
	q.Set("from", now.Add(-time.Duration(hours*float64(time.Hour))).Format(time.RFC3339))
	q.Set("to", now.Format(time.RFC3339))
	if v := flagValue(args, "-edge", ""); v != "" {
		q.Set("node_name", v)
	}
	if v := flagValue(args, "-proxy", ""); v != "" {
		q.Set("proxy", v)
	}

	if sub == "tls" {
		q.Set("limit", flagValue(args, "-limit", "30"))
		var rows []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/prism/tls-fingerprints?"+q.Encode(), nil, &rows); err != nil {
			fmt.Fprintf(os.Stderr, "prism tls : %v\n", err)
			os.Exit(1)
		}
		if len(rows) == 0 {
			fmt.Println("(aucune empreinte TLS)")
			return
		}
		for _, r := range rows {
			fmt.Printf("%-40s requêtes=%-8.0f erreurs=%-7.0f signalées=%-7.0f ip=%-6.0f ja3=%s\n",
				firstString(r["ja4"]), num(r["requests"]), num(r["errors"]), num(r["flagged"]), num(r["unique_ips"]), firstString(r["ja3"]))
		}
		return
	}

	if sub == "anomalies" {
		var list []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/prism/anomalies?"+q.Encode(), nil, &list); err != nil {
			fmt.Fprintf(os.Stderr, "prism anomalies : %v\n", err)
			os.Exit(1)
		}
		if len(list) == 0 {
			fmt.Println("(aucune anomalie)")
			return
		}
		for _, a := range list {
			fmt.Printf("%-9s %-15s %-24s valeur=%.1f requêtes=%.0f\n", a["level"], a["kind"], firstString(a["label"], a["subject"]), num(a["value"]), num(a["count"]))
		}
		return
	}

	city := flagValue(args, "-level", "country") == "city"
	path := "/api/v1/prism/geo"
	if city {
		path += "/points"
		q.Set("limit", flagValue(args, "-limit", "50"))
	}
	var rows []map[string]any
	if _, err := client.DoJSON("GET", path+"?"+q.Encode(), nil, &rows); err != nil {
		fmt.Fprintf(os.Stderr, "prism geo : %v\n", err)
		os.Exit(1)
	}
	if len(rows) == 0 {
		fmt.Println("(aucune donnée)")
		return
	}
	for _, r := range rows {
		place := firstString(r["country_name"])
		if city {
			place = fmt.Sprintf("%s (%s)", firstString(r["city"], r["region"], r["country_name"]), r["country_code"])
		}
		fmt.Printf("%-34s requêtes=%-8.0f erreurs=%-7.0f tx_err=%5.1f%% bannies=%.0f\n",
			place, num(r["requests"]), num(r["errors"]), num(r["error_rate"]), num(r["banned_ips"]))
	}
}

func num(v any) float64 {
	f, _ := v.(float64)
	return f
}

func firstString(vs ...any) string {
	for _, v := range vs {
		if s, _ := v.(string); s != "" {
			return s
		}
	}
	return ""
}
