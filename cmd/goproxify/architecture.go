// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
)

func runArchitecture() {
	sub := subcommand(os.Args, 2)
	switch sub {
	case "versions":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var versions []map[string]any
		if _, err := client.DoJSON("GET", "/api/v1/architecture/versions", nil, &versions); err != nil {
			fmt.Fprintf(os.Stderr, "architecture versions : %v\n", err)
			os.Exit(1)
		}
		if len(versions) == 0 {
			fmt.Println("(aucune version conservée)")
			return
		}
		fmt.Printf("%-48s  %-25s  %s\n", "VERSION", "ENREGISTRÉE", "TAILLE")
		fmt.Println(strings.Repeat("-", 90))
		for _, v := range versions {
			fmt.Printf("%-48v  %-25v  %v\n", v["name"], v["saved_at"], v["size"])
		}

	case "show":
		args := parseFlags(os.Args[3:])
		path := "/api/v1/architecture"
		if v := flagValue(args, "-version", ""); v != "" {
			path += "/versions/" + v
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var arch map[string]any
		if _, err := client.DoJSON("GET", path, nil, &arch); err != nil {
			fmt.Fprintf(os.Stderr, "architecture show : %v\n", err)
			os.Exit(1)
		}
		out, _ := json.MarshalIndent(arch, "", "  ")
		fmt.Println(string(out))

	case "restore":
		args := parseFlags(os.Args[3:])
		name := flagValue(args, "-name", "")
		if name == "" {
			fmt.Fprintln(os.Stderr, "usage: goproxify architecture restore -name <version>")
			os.Exit(1)
		}
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		var out map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/architecture/restore", map[string]string{"name": name}, &out, 200); err != nil {
			fmt.Fprintf(os.Stderr, "architecture restore : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("architecture.json restauré depuis %s (l'état précédent est conservé).\n", name)

	case "recover":
		args := parseFlags(os.Args[3:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		body := map[string]any{}
		if edges := flagValue(args, "-edges", ""); edges != "" {
			body["edges"] = strings.Split(edges, ",")
		}
		var out struct {
			Cards       int      `json:"cards"`
			Unreachable []string `json:"unreachable"`
			Added       struct {
				Groups  []string `json:"groups"`
				Nodes   int      `json:"nodes"`
				Joined  int      `json:"joined"`
				Domains int      `json:"domains"`
				Skipped int      `json:"skipped"`
			} `json:"added"`
		}
		if _, err := client.DoJSON("POST", "/api/v1/architecture/recover", body, &out, 200); err != nil {
			fmt.Fprintf(os.Stderr, "architecture recover : %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("%d fiche(s) de groupe lue(s) : groupes %s — %d passerelle(s) ajoutée(s), %d rattachée(s) à leur groupe, %d domaine(s) ajouté(s), %d déjà connu(s).\n",
			out.Cards, strings.Join(out.Added.Groups, ", "), out.Added.Nodes, out.Added.Joined, out.Added.Domains, out.Added.Skipped)
		for _, u := range out.Unreachable {
			fmt.Fprintf(os.Stderr, "  injoignable : %s\n", u)
		}

	case "group-attributes":
		if len(os.Args) < 4 || strings.HasPrefix(os.Args[3], "-") {
			fmt.Fprintln(os.Stderr, "usage: goproxify architecture group-attributes <groupe> [-environment <env>] [-region <région>] [-tags a,b]")
			os.Exit(1)
		}
		group := os.Args[3]
		args := parseFlags(os.Args[4:])
		client, err := newAdminClient(args)
		if err != nil {
			fmt.Fprintf(os.Stderr, "erreur : %v\n", err)
			os.Exit(1)
		}
		path := "/api/v1/architecture/groups/" + group + "/attributes"
		var attrs struct {
			Environment string   `json:"environment"`
			Region      string   `json:"region"`
			Tags        []string `json:"tags"`
		}
		if _, err := client.DoJSON("GET", path, nil, &attrs); err != nil {
			fmt.Fprintf(os.Stderr, "architecture group-attributes : %v\n", err)
			os.Exit(1)
		}
		_, setEnv := args["-environment"]
		_, setRegion := args["-region"]
		_, setTags := args["-tags"]
		if setEnv || setRegion || setTags {
			if setEnv {
				attrs.Environment = flagValue(args, "-environment", "")
			}
			if setRegion {
				attrs.Region = flagValue(args, "-region", "")
			}
			if setTags {
				attrs.Tags = nil
				if v := flagValue(args, "-tags", ""); v != "" {
					attrs.Tags = strings.Split(v, ",")
				}
			}
			if _, err := client.DoJSON("PUT", path, attrs, &attrs, 200); err != nil {
				fmt.Fprintf(os.Stderr, "architecture group-attributes : %v\n", err)
				os.Exit(1)
			}
		}
		fmt.Printf("groupe %s — environnement : %s · région : %s · tags : %s\n", group,
			orDash(attrs.Environment), orDash(attrs.Region), orDash(strings.Join(attrs.Tags, ", ")))

	default:
		fmt.Fprintln(os.Stderr, "usage: goproxify architecture show [-version <nom>] | versions | restore -name <version> | recover [-edges nom1,nom2] | group-attributes <groupe> [-environment e] [-region r] [-tags a,b]")
		os.Exit(1)
	}
}
