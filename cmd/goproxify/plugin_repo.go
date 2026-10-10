// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"strings"
)

func pluginClient(args map[string]string) *adminClient {
	client, err := newAdminClient(args)
	if err != nil {
		fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
		os.Exit(1)
	}
	return client
}

// plugin repo list|add|delete : dépôts de plugins (index JSON servis en HTTPS).
func runPluginRepo() {
	sub := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	client := pluginClient(args)
	switch sub {
	case "list", "ls", "":
		var repos []struct {
			ID           string `json:"id"`
			Name         string `json:"name"`
			URL          string `json:"url"`
			AllowPrivate bool   `json:"allow_private"`
		}
		if _, err := client.DoJSON("GET", "/api/v1/plugin-repos", nil, &repos); err != nil {
			fmt.Fprintf(os.Stderr, "plugin repo list : %v\n", err)
			os.Exit(1)
		}
		if len(repos) == 0 {
			fmt.Println("(aucun dépôt de plugins)")
			return
		}
		for _, r := range repos {
			priv := ""
			if r.AllowPrivate {
				priv = "  [réseau interne autorisé]"
			}
			fmt.Printf("%s  %-20s  %s%s\n", r.ID, r.Name, r.URL, priv)
		}
	case "add":
		name, u := flagValue(args, "-name", ""), flagValue(args, "-url", "")
		_, priv := args["-allow-private"]
		if name == "" || u == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify plugin repo add -name <nom> -url <https://…/index.json> [-allow-private]")
			os.Exit(1)
		}
		var out struct {
			ID string `json:"id"`
		}
		if _, err := client.DoJSON("POST", "/api/v1/plugin-repos", map[string]any{"name": name, "url": u, "allow_private": priv}, &out, 201); err != nil {
			fmt.Fprintf(os.Stderr, "plugin repo add : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Dépôt %s enregistré (%s).\n", name, out.ID)
	case "delete", "rm":
		id := flagValue(args, "-id", "")
		if id == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify plugin repo delete -id <id>")
			os.Exit(1)
		}
		if _, err := client.DoJSON("DELETE", "/api/v1/plugin-repos/"+url.PathEscape(id), nil, nil, 200, 204); err != nil {
			fmt.Fprintf(os.Stderr, "plugin repo delete : %v\n", err)
			os.Exit(1)
		}
		fmt.Println("Dépôt retiré (les plugins déjà installés ne sont pas retirés).")
	default:
		fmt.Fprintf(os.Stderr, "sous-commande plugin repo inconnue : %q\n", sub)
		os.Exit(1)
	}
}

// plugin catalog : plugins proposés par les dépôts, avec l'état d'installation.
func runPluginCatalog() {
	args := parseFlags(os.Args[3:])
	client := pluginClient(args)
	path := "/api/v1/plugin-repos/catalog"
	if repo := flagValue(args, "-repo", ""); repo != "" {
		path += "?repo=" + url.QueryEscape(repo)
	}
	var out struct {
		Entries []struct {
			RepoID           string   `json:"repo_id"`
			RepoName         string   `json:"repo_name"`
			Name             string   `json:"name"`
			Version          string   `json:"version"`
			Description      string   `json:"description"`
			Hooks            []string `json:"hooks"`
			Signed           bool     `json:"signed"`
			InstalledVersion string   `json:"installed_version"`
			UpdateAvailable  bool     `json:"update_available"`
		} `json:"entries"`
		Errors []map[string]string `json:"errors"`
	}
	if _, err := client.DoJSON("GET", path, nil, &out); err != nil {
		fmt.Fprintf(os.Stderr, "plugin catalog : %v\n", err)
		os.Exit(1)
	}
	for _, e := range out.Errors {
		fmt.Fprintf(os.Stderr, "dépôt %s : %s\n", e["repo_name"], e["error"])
	}
	if len(out.Entries) == 0 {
		fmt.Println("(catalogue vide)")
		return
	}
	fmt.Printf("%-24s  %-10s  %-12s  %-8s  %-22s  %s\n", "NOM", "VERSION", "HOOKS", "SIGNÉ", "INSTALLÉ", "DÉPÔT")
	fmt.Println(strings.Repeat("-", 100))
	for _, e := range out.Entries {
		state := "-"
		if e.InstalledVersion != "" {
			state = e.InstalledVersion
			if e.UpdateAvailable {
				state += " (mise à jour)"
			}
		}
		signed := "non"
		if e.Signed {
			signed = "oui"
		}
		fmt.Printf("%-24s  %-10s  %-12s  %-8s  %-22s  %s\n", e.Name, e.Version, strings.Join(e.Hooks, ","), signed, state, e.RepoName)
	}
}

// plugin fetch <nom> -repo <id> [-version v] : installe (ou met à jour) un plugin depuis un dépôt.
func runPluginFetch() {
	args := parseFlags(os.Args[3:])
	name := firstPositional(os.Args[3:], args)
	repo := flagValue(args, "-repo", "")
	if name == "" || repo == "" {
		fmt.Fprintln(os.Stderr, "usage: goproxify plugin fetch <nom> -repo <id> [-version <v>]")
		os.Exit(1)
	}
	client := pluginClient(args)
	var out struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		SHA256  string `json:"sha256"`
	}
	body := map[string]any{"repo_id": repo, "name": name, "version": flagValue(args, "-version", "")}
	if _, err := client.DoJSON("POST", "/api/v1/plugin-repos/install", body, &out, 200, 201); err != nil {
		fmt.Fprintf(os.Stderr, "plugin fetch : %v\n", err)
		os.Exit(1)
	}
	fmt.Printf("Plugin %s %s installé (sha256 %s).\n", out.Name, out.Version, out.SHA256)
}
