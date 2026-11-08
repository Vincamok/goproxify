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

func runMe() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "get", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/me", nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "me get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "update":
		args := parseFlags(os.Args[3:])
		payload := map[string]any{}
		if v := flagValue(args, "-email", ""); v != "" {
			payload["email"] = v
		}
		if len(payload) == 0 {
			fmt.Fprintln(os.Stderr, "usage: goproxify me update [-email <email>]")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("PATCH", "/api/v1/me", payload, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "me update : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Profil mis à jour.")

	case "passwd":
		args := parseFlags(os.Args[3:])
		current := flagValue(args, "-current", "")
		newpwd := flagValue(args, "-password", "")
		if current == "" || newpwd == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify me passwd -current <mdp-actuel> -password <nouveau-mdp>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("POST", "/api/v1/me/change-password",
			map[string]any{"current_password": current, "new_password": newpwd},
			nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "me passwd : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Mot de passe modifié.")

	case "tokens":
		runMeTokens()

	case "help":
		fmt.Print(`Usage: goproxify me <sous-commande> [options]

Sous-commandes :
  get     Affiche le profil de l'utilisateur courant
  update  Modifie l'email du compte courant
  passwd  Change le mot de passe
  tokens  Gestion des tokens API personnels (PAT)

goproxify me get    [-admin-url …] [-token …]
goproxify me update [-email <email>] [-admin-url …] [-token …]
goproxify me passwd -current <mdp-actuel> -password <nouveau-mdp> [-admin-url …] [-token …]

goproxify me tokens list   [-admin-url …] [-token …]
goproxify me tokens scopes [-admin-url …] [-token …]
goproxify me tokens create -label <nom> -scopes <s1,s2,…> [-audience api|mcp|both] [-expires <RFC3339>] [-admin-url …] [-token …]
goproxify me tokens revoke <id> [-admin-url …] [-token …]
goproxify me tokens delete <id> [-admin-url …] [-token …]
goproxify me tokens purge  [-admin-url …] [-token …]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande me inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify me help")
		os.Exit(1)
	}
}

func runMeTokens() {
	sub := subcommand(os.Args, 3)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var tokens []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/me/tokens", nil, &tokens); err != nil {
			fmt.Fprintf(os.Stderr, "me tokens list : %v\n", err)
			os.Exit(1)
		}
		if len(tokens) == 0 {
			fmt.Println("(aucun token)")
			return
		}
		fmt.Printf("%-36s  %-25s  %-15s  %-6s  %-20s  %s\n", "ID", "LABEL", "PRÉFIXE", "USAGE", "EXPIRATION", "SCOPES")
		fmt.Println(strings.Repeat("-", 118))
		for _, t := range tokens {
			id, _ := t["id"].(string)
			label, _ := t["label"].(string)
			prefix, _ := t["prefix"].(string)
			audience, _ := t["audience"].(string)
			expires, _ := t["expires_at"].(string)
			if expires == "" {
				expires = "permanent"
			} else if len(expires) > 19 {
				expires = expires[:10]
			}
			scopes := ""
			if s, ok := t["scopes"].([]any); ok {
				parts := make([]string, 0, len(s))
				for _, v := range s {
					if str, ok := v.(string); ok {
						parts = append(parts, str)
					}
				}
				scopes = strings.Join(parts, ", ")
				if len(scopes) > 40 {
					scopes = scopes[:37] + "…"
				}
			}
			fmt.Printf("%-36s  %-25s  %-15s  %-6s  %-20s  %s\n", id, label, prefix, audience, expires, scopes)
		}

	case "scopes":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var scopes []struct {
			ID        string   `json:"id"`
			Available bool     `json:"available"`
			Tools     []string `json:"tools"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/me/tokens/scopes", nil, &scopes); err != nil {
			fmt.Fprintf(os.Stderr, "me tokens scopes : %v\n", err)
			os.Exit(1)
		}
		n := 0
		for _, s := range scopes {
			if !s.Available {
				continue
			}
			n++
			fmt.Printf("%-18s  %d outil(s) MCP\n", s.ID, len(s.Tools))
		}
		if n == 0 {
			fmt.Println("(aucun scope disponible)")
		}

	case "create":
		args := parseFlags(os.Args[4:])
		label := flagValue(args, "-label", "")
		scopesStr := flagValue(args, "-scopes", "")
		if label == "" || scopesStr == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify me tokens create -label <nom> -scopes <s1,s2,…> [-audience api|mcp|both] [-expires <RFC3339>]")
			os.Exit(1)
		}
		scopes := strings.Split(scopesStr, ",")
		for i, s := range scopes {
			scopes[i] = strings.TrimSpace(s)
		}
		payload := map[string]any{
			"label":  label,
			"scopes": scopes,
		}
		if exp := flagValue(args, "-expires", ""); exp != "" {
			payload["expires_at"] = exp
		}
		if aud := flagValue(args, "-audience", ""); aud != "" {
			payload["audience"] = aud
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var result map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/me/tokens", payload, &result, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "me tokens create : %v\n", err)
			os.Exit(1)
		}
		id, _ := result["id"].(string)
		token, _ := result["token"].(string)
		fmt.Printf("Token créé : %s\n", id)
		if token != "" {
			fmt.Printf("Valeur (copiez-la, elle ne sera plus affichée) :\n  %s\n", token)
		}

	case "revoke":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify me tokens revoke <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/me/tokens/"+url.PathEscape(id),
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "me tokens revoke : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token %s révoqué.\n", id)

	case "delete":
		args := parseFlags(os.Args[4:])
		id := firstPositional(os.Args[4:], args)
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify me tokens delete <id>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/me/tokens/"+url.PathEscape(id)+"?purge=1",
			nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "me tokens delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Token %s supprimé.\n", id)

	case "purge":
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var tokens []struct {
			ID        string `json:"id"`
			Revoked   bool   `json:"revoked"`
			ExpiresAt string `json:"expires_at"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/me/tokens", nil, &tokens); err != nil {
			fmt.Fprintf(os.Stderr, "me tokens purge : %v\n", err)
			os.Exit(1)
		}
		n := 0
		for _, t := range tokens {
			expired := false
			if t.ExpiresAt != "" {
				if at, err := time.Parse(time.RFC3339, t.ExpiresAt); err == nil && !at.After(time.Now()) {
					expired = true
				}
			}
			if !t.Revoked && !expired {
				continue
			}
			if _, err := client.DoJSON("DELETE", "/api/v1/me/tokens/"+url.PathEscape(t.ID)+"?purge=1",
				nil, nil, 200, 204); err != nil {
				fmt.Fprintf(os.Stderr, "me tokens purge : %s : %v\n", t.ID, err)
				continue
			}
			n++
		}
		fmt.Printf("%d token(s) révoqué(s) ou expiré(s) supprimé(s).\n", n)

	default:
		fmt.Fprintf(os.Stderr, "sous-commande me tokens inconnue : %q\n", sub)
		os.Exit(1)
	}
}
