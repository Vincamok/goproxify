// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"os"
	"strings"
)

func runContainers() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var containers []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/discovered-containers", nil, &containers); err != nil {
			fmt.Fprintf(os.Stderr, "containers list : %v\n", err)
			os.Exit(1)
		}
		if len(containers) == 0 {
			fmt.Println("(aucun conteneur découvert)")
			return
		}
		fmt.Printf("%-40s  %-10s  %-20s  %-20s  %-38s  %s\n", "HOST", "TLS", "EDGE", "AGENT", "REMPLACÉ PAR (proxy)", "BACKENDS")
		fmt.Println(strings.Repeat("-", 150))
		for _, c := range containers {
			host, _ := c["host"].(string)
			tls := "non"
			if t, ok := c["tls"].(bool); ok && t {
				tls = "oui"
			}
			edge, _ := c["edge_name"].(string)
			agent, _ := c["agent_name"].(string)
			backends := ""
			if b, ok := c["backends"].([]any); ok {
				parts := make([]string, 0, len(b))
				for _, v := range b {
					if s, ok := v.(string); ok {
						parts = append(parts, s)
					}
				}
				backends = strings.Join(parts, ", ")
				if len(backends) > 40 {
					backends = backends[:37] + "…"
				}
			}
			shadowed, _ := c["shadowed_by"].(string)
			if shadowed == "" {
				shadowed = "-"
			}
			fmt.Printf("%-40s  %-10s  %-20s  %-20s  %-38s  %s\n", host, tls, edge, agent, shadowed, backends)
		}

	case "convert":
		args := parseFlags(os.Args[3:])
		pos := positionalArgs(os.Args[3:])
		id := flagValue(args, "-id", "")
		if id == "" && len(pos) > 0 {
			id = pos[0]
		}
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify containers convert <id> [-edge <passerelle>]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var out struct {
			ID   string `json:"id"`
			Name string `json:"name"`
		}
		body := map[string]any{"id": id, "edge": flagValue(args, "-edge", "")}
		if _, err := client.DoJSON("POST", "/api/v1/proxies/from-discovered", body, &out, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "containers convert : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Proxy %s créé pour %s (modifiable avec « goproxify proxy »).\n", out.ID, out.Name)

	case "help":
		fmt.Print(`Usage: goproxify containers [list] [options]

Affiche les conteneurs découverts par les Agents et les convertit en proxys.
Agrège les résultats de toutes les passerelles connectées.

goproxify containers list [-admin-url …] [-token …]
goproxify containers      [-admin-url …] [-token …]
goproxify containers convert <id> [-edge <passerelle>] [-admin-url …] [-token …]

  convert crée un proxy modifiable à partir de la route issue des labels (<id> : l'hôte,
  ex. app.example.fr, ou l'id de l'API). Le proxy prend la place de la route des labels
  sur son hôte ; désactivé ou supprimé, il la lui rend.
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande containers inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify containers help")
		os.Exit(1)
	}
}
