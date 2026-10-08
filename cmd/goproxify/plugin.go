// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

func runPlugin() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "list", "ls", "":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var list []struct {
			Name    string   `json:"name"`
			Version string   `json:"version"`
			Hooks   []string `json:"hooks"`
			OnError string   `json:"on_error"`
			SHA256  string   `json:"sha256"`
			Size    int      `json:"size"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/plugins", nil, &list); err != nil {
			fmt.Fprintf(os.Stderr, "plugin list : %v\n", err)
			os.Exit(1)
		}
		if len(list) == 0 {
			fmt.Println("(aucun plugin)")
			return
		}
		fmt.Printf("%-24s  %-10s  %-18s  %-8s  %-8s  %s\n", "NOM", "VERSION", "HOOKS", "ERREUR", "TAILLE", "SHA-256")
		fmt.Println(strings.Repeat("-", 100))
		for _, p := range list {
			sum := p.SHA256
			if len(sum) > 12 {
				sum = sum[:12] + "…"
			}
			fmt.Printf("%-24s  %-10s  %-18s  %-8s  %-8d  %s\n", p.Name, p.Version, strings.Join(p.Hooks, ","), p.OnError, p.Size, sum)
		}

	case "get":
		args := parseFlags(os.Args[3:])
		name := firstPositional(os.Args[3:], args)
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify plugin get <nom>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var p json.RawMessage
		if _, err := client.DoJSON("GET", "/api/v1/plugins/"+url.PathEscape(name), nil, &p); err != nil {
			fmt.Fprintf(os.Stderr, "plugin get : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(p, "", "  ")
		fmt.Println(string(out))

	case "install", "update":
		args := parseFlags(os.Args[3:])
		manifestFile := flagValue(args, "-manifest", "")
		wasmFile := flagValue(args, "-wasm", "")
		if manifestFile == "" || wasmFile == "" {
			fmt.Fprintf(os.Stderr, "usage: goproxify plugin %s -manifest <plugin.json> -wasm <plugin.wasm> [-sha256 <empreinte>]\n", sub)
			os.Exit(1)
		}
		mdata, err := os.ReadFile(manifestFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture du manifeste : %v\n", err)
			os.Exit(1)
		}
		var manifest map[string]any
		if err := json.Unmarshal(mdata, &manifest); err != nil {
			fmt.Fprintf(os.Stderr, "manifeste JSON invalide : %v\n", err)
			os.Exit(1)
		}
		wasm, err := os.ReadFile(wasmFile)
		if err != nil {
			fmt.Fprintf(os.Stderr, "lecture du module : %v\n", err)
			os.Exit(1)
		}
		sum := sha256.Sum256(wasm)
		got := hex.EncodeToString(sum[:])
		// L'empreinte attendue est facultative en ligne de commande, mais si elle est donnée (publiée par
		// l'auteur du plugin), elle doit correspondre : on n'installe pas un module qu'on n'a pas vérifié.
		if want := flagValue(args, "-sha256", ""); want != "" && !strings.EqualFold(want, got) {
			fmt.Fprintf(os.Stderr, "empreinte SHA-256 différente de celle attendue (module : %s)\n", got)
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		payload := map[string]any{"manifest": manifest, "sha256": got, "wasm": wasm}
		name, _ := manifest["name"].(string)
		method, path := "POST", "/api/v1/plugins"
		if sub == "update" {
			method, path = "PUT", "/api/v1/plugins/"+url.PathEscape(name)
		}
		if _, err := client.DoJSON(method, path, payload, nil, 200, 201); err != nil {
			fmt.Fprintf(os.Stderr, "plugin %s : %v\n", sub, err)
			os.Exit(1)
		}
		fmt.Printf("Plugin %s installé (sha256 %s).\n", name, got)

	case "delete", "rm":
		args := parseFlags(os.Args[3:])
		name := firstPositional(os.Args[3:], args)
		_, force := args["-y"]
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify plugin delete <nom> [-y]")
			os.Exit(1)
		}
		if !force {
			fmt.Printf("Supprimer le plugin %q ? Les routes qui l'utilisent refuseront le trafic (503). [y/N] ", name)
			var confirm string
			fmt.Scanln(&confirm) //nolint:errcheck
			if strings.ToLower(confirm) != "y" {
				fmt.Println("Annulé.")
				return
			}
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/plugins/"+url.PathEscape(name), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "plugin delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Plugin %s supprimé.\n", name)

	case "help":
		fmt.Print(`Usage: goproxify plugin <sous-commande> [options]

Plugins WebAssembly exécutés par les passerelles (ADR 0008). Installer un plugin fait exécuter du code
sur les passerelles : réservé aux administrateurs.

Sous-commandes :
  list     Liste les plugins installés
  get      Affiche un plugin (manifeste, empreinte, taille)
  install  Installe un plugin depuis son manifeste et son module .wasm
  update   Remplace un plugin installé
  delete   Supprime un plugin

goproxify plugin list    [-admin-url …] [-token …]
goproxify plugin get     <nom> [-admin-url …] [-token …]
goproxify plugin install -manifest <plugin.json> -wasm <plugin.wasm> [-sha256 <empreinte>] [-admin-url …] [-token …]
goproxify plugin update  -manifest <plugin.json> -wasm <plugin.wasm> [-sha256 <empreinte>] [-admin-url …] [-token …]
goproxify plugin delete  <nom> [-y] [-admin-url …] [-token …]

Exemple de manifeste plugin.json :
  {
    "name": "geo-headers", "version": "1.0.0", "api_version": 1,
    "hooks": ["request"], "on_error": "deny",
    "limits": { "memory_pages": 16, "timeout_ms": 50 },
    "fields": [ { "key": "header", "label": "En-tête", "kind": "text", "required": true } ]
  }

Un plugin s'attache à une route avec : "plugins": [ { "name": "geo-headers", "config": { "header": "X-Geo" } } ]
`)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande plugin inconnue : %q\n", sub)
		fmt.Fprintln(os.Stderr, "utilisez : goproxify plugin help")
		os.Exit(1)
	}
}
