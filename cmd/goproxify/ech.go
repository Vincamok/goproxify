// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runECH() {
	sub := subcommand(os.Args, 2)
	args := parseFlags(os.Args[3:])
	switch sub {
	case "status", "show", "":
		echPrint(echCall(args, "GET", "/api/v1/ech", nil))

	case "enable":
		name := firstPositional(os.Args[3:], args)
		if name == "" {
			name = flagValue(args, "-public-name", "")
		}
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify ech enable <nom-public> [-admin-url …] [-token …]")
			os.Exit(1)
		}
		echPrint(echCall(args, "PUT", "/api/v1/ech", map[string]any{"enabled": true, "public_name": name}))

	case "disable":
		echPrint(echCall(args, "PUT", "/api/v1/ech", map[string]any{"enabled": false}))

	case "rotate":
		echPrint(echCall(args, "POST", "/api/v1/ech/rotate", nil))

	case "delete-key":
		id := firstPositional(os.Args[3:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify ech delete-key <id> [-admin-url …] [-token …]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/ech/keys/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "ech delete-key : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Clé %s supprimée.\n", id)

	case "help", "-h", "--help":
		fmt.Print(`goproxify ech — Encrypted Client Hello (masque le nom du site dans le handshake TLS)

Sous-commandes :
  status       Affiche l'état et la valeur à publier dans le DNS
  enable       Active ECH avec un nom public (SNI visible) couvert par un certificat
  disable      Désactive ECH (les passerelles arrêtent de l'accepter)
  rotate       Génère une nouvelle clé ; l'ancienne reste acceptée mais n'est plus publiée
  delete-key   Supprime une clé retirée (une fois les caches DNS expirés)

goproxify ech status
goproxify ech enable ech.example.fr [-admin-url …] [-token …]
goproxify ech rotate
goproxify ech delete-key <id>
`)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande ech inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify ech help")
		os.Exit(1)
	}
}

func echCall(args map[string]string, method, path string, body any) map[string]any {
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	var out map[string]any
	if _, err := client.DoJSON(method, path, body, &out, 200); err != nil {
		fmt.Fprintf(os.Stderr, "ech : %v\n", err)
		os.Exit(1)
	}
	return out
}

func echPrint(st map[string]any) {
	enabled, _ := st["enabled"].(bool)
	name, _ := st["public_name"].(string)
	if !enabled {
		fmt.Println("ECH : désactivé")
		return
	}
	fmt.Printf("ECH : activé — nom public %s\n", name)
	if rec, _ := st["https_record"].(string); rec != "" {
		fmt.Printf("À publier dans l'enregistrement HTTPS de chaque domaine :\n  %s\n", rec)
	}
	if warns, _ := st["warnings"].([]any); len(warns) > 0 {
		fmt.Printf("⚠ aucun certificat ne couvre le nom public %s\n", name)
	}
	if keys, _ := st["keys"].([]any); len(keys) > 0 {
		fmt.Printf("\n%-36s  %-9s  %-8s  %s\n", "ID", "CONFIG_ID", "ÉTAT", "CRÉÉE")
		fmt.Println(strings.Repeat("-", 80))
		for _, k := range keys {
			m, _ := k.(map[string]any)
			state := "active"
			if r, _ := m["retired"].(bool); r {
				state = "retirée"
			}
			cid, _ := m["config_id"].(float64)
			fmt.Printf("%-36v  %-9d  %-8s  %v\n", m["id"], int(cid), state, m["created_at"])
		}
	}
}
