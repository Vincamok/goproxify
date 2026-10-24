// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

func runLogsSIEM() {
	action := subcommand(os.Args, 3)
	args := parseFlags(os.Args[min(4, len(os.Args)):])
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	switch action {
	case "show", "":
		var cfg json.RawMessage
		if _, err := client.DoJSON("GET", "/api/v1/logs/siem", nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "siem show : %v\n", err)
			os.Exit(1)
		}
		printJSON(cfg)

	case "set":
		file := flagValue(args, "-file", "")
		_, stdin := args["-stdin"]
		if file == "" && !stdin {
			fmt.Fprintln(os.Stderr, "usage: goproxify logs siem set --file <fichier.json> | --stdin")
			os.Exit(1)
		}
		var data []byte
		if stdin {
			data, err = io.ReadAll(os.Stdin)
		} else {
			data, err = os.ReadFile(file)
		}
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture : %v\n", err)
			os.Exit(1)
		}
		var body json.RawMessage = data
		if !json.Valid(data) {
			fmt.Fprintln(os.Stderr, "le fichier n'est pas du JSON valide")
			os.Exit(1)
		}
		var saved struct {
			Enabled      bool `json:"enabled"`
			Destinations []struct {
				Name string `json:"name"`
			} `json:"destinations"`
		}
		if _, err := client.DoJSON("PUT", "/api/v1/logs/siem", body, &saved); err != nil {
			fmt.Fprintf(os.Stderr, "siem set : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Configuration enregistrée et envoyée aux passerelles : exporteur %s, %d destination(s)\n", map[bool]string{true: "actif", false: "éteint"}[saved.Enabled], len(saved.Destinations))

	case "enable", "disable":
		var cfg map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/logs/siem", nil, &cfg); err != nil {
			fmt.Fprintf(os.Stderr, "siem %s : %v\n", action, err)
			os.Exit(1)
		}
		cfg["enabled"] = action == "enable"
		if _, err := client.DoJSON("PUT", "/api/v1/logs/siem", cfg, nil); err != nil {
			fmt.Fprintf(os.Stderr, "siem %s : %v\n", action, err)
			os.Exit(1)
		}
		fmt.Printf("Exporteur SIEM %s\n", map[string]string{"enable": "activé", "disable": "éteint"}[action])

	case "status":
		var result struct {
			Nodes []struct {
				NodeName     string `json:"node_name"`
				ReportedAt   string `json:"reported_at"`
				Stale        bool   `json:"stale"`
				Destinations []struct {
					Name      string `json:"name"`
					Type      string `json:"type"`
					State     string `json:"state"`
					Delivered int64  `json:"delivered"`
					LagSec    int64  `json:"lag_sec"`
					AtRisk    bool   `json:"at_risk"`
					LastError string `json:"last_error"`
				} `json:"destinations"`
			} `json:"nodes"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/logs/siem/status", nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "siem status : %v\n", err)
			os.Exit(1)
		}
		if len(result.Nodes) == 0 {
			fmt.Println("Aucune passerelle n'a rapporté d'état d'export.")
			return
		}
		for _, n := range result.Nodes {
			note := ""
			if n.Stale {
				note = " (état périmé : passerelle muette)"
			}
			fmt.Printf("%s%s\n", n.NodeName, note)
			if len(n.Destinations) == 0 {
				fmt.Println("  aucune destination active")
			}
			for _, d := range n.Destinations {
				line := fmt.Sprintf("  %-24s %-7s %-9s livrées=%d retard=%s", d.Name, d.Type, d.State, d.Delivered, (time.Duration(d.LagSec) * time.Second).String())
				if d.AtRisk {
					line += "  À RISQUE (lignes bientôt purgées)"
				}
				if d.LastError != "" {
					line += "  erreur : " + strings.TrimSpace(d.LastError)
				}
				fmt.Println(line)
			}
		}

	default:
		fmt.Fprintf(os.Stderr, "action siem inconnue : %q\nutilisez : goproxify logs help\n", action)
		os.Exit(1)
	}
}
