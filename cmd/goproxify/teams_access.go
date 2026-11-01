// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

// perimeterFromFlags lit les critères d'un périmètre : tous ceux qui sont posés sont requis.
func perimeterFromFlags(args map[string]string) (map[string]any, error) {
	p := map[string]any{}
	for flag, key := range map[string]string{"-domain": "domain", "-proxy": "proxy", "-backend": "backend"} {
		if v := flagValue(args, flag, ""); v != "" {
			p[key] = v
		}
	}
	group := map[string]string{}
	for flag, key := range map[string]string{"-group": "name", "-environment": "environment", "-region": "region", "-tag": "tag"} {
		if v := flagValue(args, flag, ""); v != "" {
			group[key] = v
		}
	}
	if len(group) > 0 {
		p["group"] = group
	}
	if v := flagValue(args, "-label", ""); v != "" {
		labels := map[string]string{}
		for _, kv := range strings.Split(v, ",") {
			k, val, ok := strings.Cut(strings.TrimSpace(kv), "=")
			if !ok {
				return nil, fmt.Errorf("-label %q : attendu clé=valeur[,clé=valeur]", kv)
			}
			labels[k] = val
		}
		p["labels"] = labels
	}
	return p, nil
}

func fatalf(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

func runTeamsAccess() {
	sub := subcommand(os.Args, 3)
	args := parseFlags(os.Args[4:])
	team := firstPositional(os.Args[4:], args)
	if team == "" {
		fatalf("usage: goproxify teams access list|add|remove <équipe> …")
	}
	client, err := newAdminClient(args)
	if err != nil {
		fatalf("erreur : %v", err)
	}
	base := "/api/v1/teams/" + url.PathEscape(team) + "/accesses"

	switch sub {
	case "list", "ls", "":
		var accesses []struct {
			ID          string            `json:"id"`
			Name        string            `json:"name"`
			Perimeter   map[string]any    `json:"perimeter"`
			Levels      map[string]string `json:"levels"`
			Permissions []string          `json:"permissions"`
		}
		if _, err := client.DoJSON("GET", base, nil, &accesses); err != nil {
			fatalf("teams access list : %v", err)
		}
		if len(accesses) == 0 {
			fmt.Println("(aucun accès)")
			return
		}
		for _, a := range accesses {
			fmt.Printf("%s  %s\n  périmètre : %s\n  niveaux   : %s\n", a.ID, a.Name, perimeterSummary(a.Perimeter), levelsSummary(a.Levels))
			if len(a.Permissions) > 0 {
				fmt.Printf("  cochées   : %s\n", strings.Join(a.Permissions, ", "))
			}
		}

	case "add", "set":
		body := map[string]any{"name": flagValue(args, "-name", "")}
		levels := map[string]string{}
		var permissions []string
		if profile := flagValue(args, "-profile", ""); profile != "" {
			var cat struct {
				Profiles []struct {
					ID          string            `json:"id"`
					Label       string            `json:"label"`
					Levels      map[string]string `json:"levels"`
					Permissions []string          `json:"permissions"`
				} `json:"profiles"`
			}
			if _, err := client.DoJSON("GET", "/api/v1/rights/catalog", nil, &cat); err != nil {
				fatalf("teams access : %v", err)
			}
			found := false
			for _, p := range cat.Profiles {
				if p.ID != profile {
					continue
				}
				found = true
				for k, v := range p.Levels {
					levels[k] = v
				}
				permissions = append(permissions, p.Permissions...)
				if body["name"] == "" {
					body["name"] = p.Label
				}
			}
			if !found {
				fatalf("profil %q inconnu (goproxify teams catalog)", profile)
			}
		}
		if v := flagValue(args, "-level", ""); v != "" {
			for _, kv := range strings.Split(v, ",") {
				service, level, ok := strings.Cut(strings.TrimSpace(kv), "=")
				if !ok {
					fatalf("-level %q : attendu service=niveau[,service=niveau]", kv)
				}
				levels[service] = level
			}
		}
		if v := flagValue(args, "-allow", ""); v != "" {
			permissions = append(permissions, strings.Split(v, ",")...)
		}
		perimeter, err := perimeterFromFlags(args)
		if err != nil {
			fatalf("%v", err)
		}
		body["levels"], body["permissions"], body["perimeter"] = levels, permissions, perimeter
		method, path := "POST", base
		if id := flagValue(args, "-access", ""); id != "" {
			method, path = "PUT", base+"/"+url.PathEscape(id)
		}
		var out struct {
			ID string `json:"id"`
		}
		if _, err := client.DoJSON(method, path, body, &out, 200, 201); err != nil {
			fatalf("teams access %s : %v", sub, err)
		}
		fmt.Printf("Accès %s enregistré pour l'équipe %s.\n", out.ID, team)

	case "remove", "rm":
		id := flagValue(args, "-access", "")
		if id == "" {
			fatalf("usage: goproxify teams access remove <équipe> -access <id>")
		}
		if _, err := client.DoJSON("DELETE", base+"/"+url.PathEscape(id), nil, nil, 204); err != nil {
			fatalf("teams access remove : %v", err)
		}
		fmt.Printf("Accès %s supprimé.\n", id)

	default:
		fatalf("sous-commande teams access inconnue : %q (list, add, remove)", sub)
	}
}

func perimeterSummary(p map[string]any) string {
	var parts []string
	for _, k := range []string{"domain", "proxy", "backend"} {
		if v, ok := p[k].(string); ok && v != "" {
			parts = append(parts, k+"="+v)
		}
	}
	if g, ok := p["group"].(map[string]any); ok {
		for _, k := range []string{"name", "environment", "region", "tag"} {
			if v, ok := g[k].(string); ok && v != "" {
				parts = append(parts, "groupe."+k+"="+v)
			}
		}
	}
	if l, ok := p["labels"].(map[string]any); ok {
		for k, v := range l {
			parts = append(parts, fmt.Sprintf("étiquette %s=%v", k, v))
		}
	}
	if len(parts) == 0 {
		return "tout"
	}
	sort.Strings(parts)
	return strings.Join(parts, " ET ")
}

func levelsSummary(levels map[string]string) string {
	if len(levels) == 0 {
		return "(aucun)"
	}
	parts := make([]string, 0, len(levels))
	for k, v := range levels {
		parts = append(parts, k+"="+v)
	}
	sort.Strings(parts)
	return strings.Join(parts, ", ")
}

// runTeamsCatalog affiche le vocabulaire des accès : services, niveaux et profils.
func runTeamsCatalog() {
	args := parseFlags(os.Args[3:])
	client, err := newAdminClient(args)
	if err != nil {
		fatalf("erreur : %v", err)
	}
	var cat struct {
		Services []struct {
			ID        string `json:"id"`
			Group     string `json:"group"`
			Levels    []struct{ ID, Class string }
			Explicits []struct{ ID string }
		} `json:"services"`
		Profiles []struct {
			ID, Label, Audience string
		} `json:"profiles"`
	}
	if _, err := client.DoJSON("GET", "/api/v1/rights/catalog", nil, &cat); err != nil {
		fatalf("teams catalog : %v", err)
	}
	for _, s := range cat.Services {
		var levels []string
		for _, l := range s.Levels {
			if l.Class != "platform" {
				levels = append(levels, l.ID)
			}
		}
		line := fmt.Sprintf("%-18s %-14s %s", s.ID, s.Group, strings.Join(levels, " → "))
		if len(s.Explicits) > 0 {
			var ids []string
			for _, e := range s.Explicits {
				ids = append(ids, e.ID)
			}
			line += "   [cases : " + strings.Join(ids, ", ") + "]"
		}
		fmt.Println(line)
	}
	fmt.Println("\nProfils (teams access add -profile <id>) :")
	for _, p := range cat.Profiles {
		fmt.Printf("  %-20s %s — %s\n", p.ID, p.Label, p.Audience)
	}
}

// runTeamsPreview liste les proxys qu'un périmètre couvre.
func runTeamsPreview() {
	args := parseFlags(os.Args[3:])
	client, err := newAdminClient(args)
	if err != nil {
		fatalf("erreur : %v", err)
	}
	perimeter, err := perimeterFromFlags(args)
	if err != nil {
		fatalf("%v", err)
	}
	var out struct {
		Count   int `json:"count"`
		Total   int `json:"total"`
		Proxies []struct{ Name, Host string }
	}
	if _, err := client.DoJSON("POST", "/api/v1/rights/preview", map[string]any{"perimeter": perimeter}, &out); err != nil {
		fatalf("teams preview : %v", err)
	}
	fmt.Printf("Ce périmètre couvre %d proxy(s) sur %d.\n", out.Count, out.Total)
	for _, p := range out.Proxies {
		fmt.Printf("  %s (%s)\n", p.Name, p.Host)
	}
}
