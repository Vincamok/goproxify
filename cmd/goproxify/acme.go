// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

const acmeUsage = `Usage: goproxify acme <ressource> <action> [options] [-admin-url …] [-token …]

Fournisseurs DNS du challenge ACME DNS-01. Un certificat en désigne un par son identifiant
(goproxify cert obtain <domaine> -dns-provider <id>), réutilisé au renouvellement.

goproxify acme types [-q <filtre>] [-json]                 # types (OVH, Cloudflare, libdns…) et paramètres

goproxify acme providers list   [-json]
goproxify acme providers get    <id>
goproxify acme providers add    -name <nom> -type <type> [-set clé=valeur,…] [-file params.json]
goproxify acme providers update <id> [-name <nom>] [-set clé=valeur,…] [-file params.json]
goproxify acme providers delete <id> [-y]

-set convient aux valeurs simples ; une valeur qui contient une virgule passe par -file, un objet
JSON { "clé": "valeur" }. Les secrets sont masqués à la lecture ; update conserve ceux qu'il ne
reçoit pas.
`

func runACME() {
	res, action := subcommand(os.Args, 2), subcommand(os.Args, 3)
	switch res {
	case "types":
		runACMETypes()
	case "providers":
		runACMEProviders(action)
	case "help", "":
		fmt.Print(acmeUsage)
	default:
		die("sous-commande acme inconnue : %q (goproxify acme help)", res)
	}
}

func runACMETypes() {
	_, args, client := autoArgs(3, "")
	var types []struct {
		Type   string         `json:"type"`
		Label  string         `json:"label"`
		Attrs  map[string]any `json:"attrs"`
		Fields []struct {
			Key      string `json:"key"`
			Secret   bool   `json:"secret"`
			Required bool   `json:"required"`
		} `json:"fields"`
	}
	call(client, "GET", "/api/v1/acme/provider-types", nil, &types, "acme types")
	q := strings.ToLower(flagValue(args, "-q", ""))
	shown := types[:0]
	for _, ty := range types {
		if q == "" || strings.Contains(strings.ToLower(ty.Type+" "+ty.Label), q) {
			shown = append(shown, ty)
		}
	}
	if _, ok := args["-json"]; ok {
		printJSON(shown)
		return
	}
	for _, ty := range shown {
		var fields []string
		for _, f := range ty.Fields {
			n := f.Key
			if f.Required {
				n += "*"
			}
			if f.Secret {
				n += " (secret)"
			}
			fields = append(fields, n)
		}
		engine, _ := ty.Attrs["engine"].(string)
		fmt.Printf("%-14s %-22s %-7s %s\n", ty.Type, ty.Label, engine, strings.Join(fields, ", "))
	}
	fmt.Println("\n* = champ requis")
}

func runACMEProviders(action string) {
	switch action {
	case "list", "ls", "":
		_, args, client := autoArgs(4, "")
		var list []map[string]any
		call(client, "GET", "/api/v1/acme/providers", nil, &list, "acme providers list")
		if _, ok := args["-json"]; ok {
			printJSON(list)
			return
		}
		if len(list) == 0 {
			fmt.Println("(aucun fournisseur DNS)")
			return
		}
		fmt.Printf("%-18s  %-24s  %s\n", "ID", "NOM", "TYPE")
		for _, p := range list {
			fmt.Printf("%-18s  %-24s  %s\n", str(p, "id"), str(p, "name"), str(p, "type"))
		}
	case "get":
		id, _, client := autoArgs(4, "goproxify acme providers get <id>")
		var p map[string]any
		call(client, "GET", "/api/v1/acme/providers/"+url.PathEscape(id), nil, &p, "acme providers get")
		printJSON(p)
	case "add", "create":
		_, args, client := autoArgs(4, "")
		name, typ := flagValue(args, "-name", ""), flagValue(args, "-type", "")
		if name == "" || typ == "" {
			die("usage: goproxify acme providers add -name <nom> -type <type> [-set clé=valeur,…] [-file params.json]")
		}
		body := map[string]any{"name": name, "type": typ, "params": dnsParams(nil, args)}
		var out map[string]any
		if _, err := client.DoJSON("POST", "/api/v1/acme/providers", body, &out, 201); err != nil {
			die("acme providers add : %v", err)
		}
		fmt.Printf("Fournisseur DNS créé : %s (%s)\n", str(out, "id"), name)
	case "update":
		id, args, client := autoArgs(4, "goproxify acme providers update <id> [-name <nom>] [-set clé=valeur,…] [-file params.json]")
		var cur struct {
			Name   string            `json:"name"`
			Type   string            `json:"type"`
			Params map[string]string `json:"params"`
		}
		call(client, "GET", "/api/v1/acme/providers/"+url.PathEscape(id), nil, &cur, "acme providers get")
		body := map[string]any{
			"name":   flagValue(args, "-name", cur.Name),
			"type":   cur.Type,
			"params": dnsParams(cur.Params, args),
		}
		call(client, "PUT", "/api/v1/acme/providers/"+url.PathEscape(id), body, nil, "acme providers update")
		fmt.Printf("Fournisseur DNS %s mis à jour.\n", id)
	case "delete", "rm":
		id, args, client := autoArgs(4, "goproxify acme providers delete <id> [-y]")
		if _, ok := args["-y"]; !ok {
			fmt.Printf("Supprimer le fournisseur DNS %q ? [y/N] ", id)
			var confirm string
			fmt.Scanln(&confirm) //nolint:errcheck
			if strings.ToLower(confirm) != "y" {
				fmt.Println("Annulé.")
				return
			}
		}
		call(client, "DELETE", "/api/v1/acme/providers/"+url.PathEscape(id), nil, nil, "acme providers delete")
		fmt.Printf("Fournisseur DNS %s supprimé.\n", id)
	default:
		die("action acme providers inconnue : %q (goproxify acme help)", action)
	}
}

// dnsParams part des paramètres existants (secrets masqués compris : l'API les conserve), applique
// -file puis -set. Les paramètres d'un fournisseur DNS sont des chaînes.
func dnsParams(base map[string]string, args map[string]string) map[string]string {
	out := map[string]string{}
	for k, v := range base {
		out[k] = v
	}
	if f := flagValue(args, "-file", ""); f != "" {
		var obj map[string]any
		if err := json.Unmarshal(readJSONFile(f), &obj); err != nil {
			die("-file : un objet JSON { \"clé\": \"valeur\" } est attendu : %v", err)
		}
		for k, v := range obj {
			out[k] = paramString(v)
		}
	}
	for _, kv := range strings.Split(flagValue(args, "-set", ""), ",") {
		if k, v, ok := strings.Cut(kv, "="); ok && strings.TrimSpace(k) != "" {
			out[strings.TrimSpace(k)] = strings.TrimSpace(v)
		}
	}
	return out
}

func paramString(v any) string {
	if s, ok := v.(string); ok {
		return s
	}
	b, _ := json.Marshal(v)
	return string(b)
}
