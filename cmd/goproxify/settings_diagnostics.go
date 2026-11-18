// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"time"
)

func runSettingsDiagnostics() {
	sub := subcommand(os.Args, 3)
	var rest []string
	if len(os.Args) > 4 {
		rest = os.Args[4:]
	}
	args := parseFlags(rest)
	switch sub {
	case "get", "":
		client := diagnosticsClient(args)
		var result map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/settings/diagnostics", nil, &result); err != nil {
			fmt.Fprintf(os.Stderr, "settings diagnostics get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(result, "", "  ")
		fmt.Println(string(out))

	case "enable", "disable":
		client := diagnosticsClient(args)
		on := sub == "enable"
		if _, err := client.DoJSON("PUT", "/api/v1/settings/diagnostics", map[string]any{"profiling_enabled": on}, nil, 200); err != nil {
			fmt.Fprintf(os.Stderr, "settings diagnostics %s : %v\n", sub, err)
			os.Exit(1)
		}
		if on {
			fmt.Println("Profilage activé.")
		} else {
			fmt.Println("Profilage désactivé.")
		}

	case "profile":
		typ := flagValue(args, "-type", "heap")
		q := url.Values{"type": {typ}}
		if typ == "cpu" {
			if s := flagValue(args, "-seconds", ""); s != "" {
				q.Set("seconds", s)
			}
		}
		text := typ != "cpu" && flagValue(args, "-format", "text") == "text"
		if text {
			q.Set("format", "text")
		}
		client := diagnosticsClient(args)
		client.client.Timeout = 3 * time.Minute
		data, _, _, err := client.DoRaw("GET", "/api/v1/settings/diagnostics/profile?"+q.Encode(), nil, "")
		if err != nil {
			fmt.Fprintf(os.Stderr, "settings diagnostics profile : %v\n", err)
			os.Exit(1)
		}
		if file := flagValue(args, "-out", ""); file != "" {
			if err := os.WriteFile(file, data, 0o600); err != nil {
				fmt.Fprintf(os.Stderr, "écriture : %v\n", err)
				os.Exit(1)
			}
			fmt.Printf("Profil écrit dans %s (%d octets). Lecture : go tool pprof -top %s\n", file, len(data), file)
			return
		}
		if !text {
			fmt.Fprintln(os.Stderr, "un profil pprof est binaire : utiliser -out <fichier>")
			os.Exit(1)
		}
		os.Stdout.Write(data) //nolint:errcheck

	default:
		fmt.Print(`Usage: goproxify settings diagnostics <action> [options]

  get       état de l'Admin (mémoire, goroutines, GC) et du profilage
  enable    autorise le profilage de l'Admin
  disable   l'interdit de nouveau
  profile   récupère un profil (profilage activé requis)
              -type heap|goroutine|cpu   (défaut heap)
              -seconds N                 durée du profil CPU, 60 max (défaut 30)
              -format text|pprof         heap et goroutine : texte lisible (défaut) ou fichier pprof
              -out <fichier>             obligatoire pour un profil pprof ou cpu

Lecture d'un fichier : go tool pprof -top <fichier>
`)
		if sub != "help" {
			os.Exit(1)
		}
	}
}

func diagnosticsClient(args map[string]string) *adminClient {
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	return client
}
