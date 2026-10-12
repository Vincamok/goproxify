// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"sort"
	"strings"
)

const automationUsage = `Usage: goproxify automation <ressource> <action> [options] [-admin-url …] [-token …]

Flux d'automatisation : un déclencheur (condition, événement, horaire, manuel) et des étapes. Les règles,
planifications et playbooks sont des flux ; -trigger filtre par type.

goproxify automation flows list     [-trigger condition,event|schedule|manual] [-json]
goproxify automation flows get      <id>
goproxify automation flows create   -file <flux.json>
goproxify automation flows update   <id> -file <flux.json>
goproxify automation flows delete   <id> [-y]
goproxify automation flows enable   <id>
goproxify automation flows disable  <id>
goproxify automation flows run      <id> [-dry-run] [-input clé=valeur,…]
goproxify automation flows simulate -file <flux.json> [-input clé=valeur,…]
goproxify automation flows versions <id>
goproxify automation flows restore  <id> <version>
goproxify automation flows detach   <id>
goproxify automation flows params   <id> -set clé=valeur,… [-name <nom>]

goproxify automation runs list      [-flow <id>] [-status waiting_approval,…] [-limit N] [-json]
goproxify automation runs get       <run-id>
goproxify automation runs approve   <run-id>
goproxify automation runs reject    <run-id>
goproxify automation runs cancel    <run-id>
goproxify automation runs replay    <run-id>

goproxify automation templates list
goproxify automation templates preview <id> [-set clé=valeur,…] [-flow <id>]
goproxify automation templates install <id> [-set clé=valeur,…] [-name <nom>] [-disabled]

goproxify automation catalog [-json]

goproxify automation silences list
goproxify automation silences add    -name <nom> -starts <RFC3339> -ends <RFC3339> [-flows <id1,id2>]
goproxify automation silences delete <id> [-y]

goproxify automation export [-out <fichier.yaml>]
goproxify automation import -file <automation.yaml>
`

func runAutomation() {
	res, action := subcommand(os.Args, 2), subcommand(os.Args, 3)
	switch res {
	case "flows":
		runAutomationFlows(action)
	case "runs":
		runAutomationRuns(action)
	case "templates":
		runAutomationTemplates(action)
	case "catalog":
		runAutomationCatalog()
	case "silences":
		runAutomationSilences(action)
	case "export":
		runAutomationExport()
	case "import":
		runAutomationImport()
	case "help", "":
		fmt.Print(automationUsage)
	default:
		fmt.Fprintf(os.Stderr, "sous-commande automation inconnue : %q\n", res)
		os.Exit(1)
	}
}

func die(format string, a ...any) {
	fmt.Fprintf(os.Stderr, format+"\n", a...)
	os.Exit(1)
}

// autoArgs retourne l'argument positionnel (identifiant) attendu en position idx et les options qui suivent.
func autoArgs(idx int, usage string) (string, map[string]string, *adminClient) {
	id := ""
	start := idx
	if usage != "" {
		id = subcommand(os.Args, idx)
		if id == "" {
			die("usage: %s", usage)
		}
		start++
	}
	if start > len(os.Args) {
		start = len(os.Args)
	}
	args := parseFlags(os.Args[start:])
	client, err := newAdminClient(args)
	if err != nil {
		die("erreur : %v", err)
	}
	return id, args, client
}

func readJSONFile(path string) json.RawMessage {
	if path == "" {
		die("-file requis")
	}
	data, err := os.ReadFile(path)
	if err != nil {
		die("lecture fichier : %v", err)
	}
	var v json.RawMessage
	if err := json.Unmarshal(data, &v); err != nil {
		die("JSON invalide : %v", err)
	}
	return v
}

// keyValues lit « a=1,b=deux » ; un nombre ou un booléen garde son type.
func keyValues(raw string) map[string]any {
	out := map[string]any{}
	for _, kv := range strings.Split(raw, ",") {
		k, v, ok := strings.Cut(strings.TrimSpace(kv), "=")
		if !ok || k == "" {
			continue
		}
		var typed any
		if json.Unmarshal([]byte(v), &typed) == nil {
			switch typed.(type) {
			case float64, bool:
				out[k] = typed
				continue
			}
		}
		out[k] = v
	}
	return out
}

func call(client *adminClient, method, path string, body, out any, what string) {
	if _, err := client.DoJSON(method, path, body, out, 200, 204); err != nil {
		die("%s : %v", what, err)
	}
}

func str(m map[string]any, key string) string {
	s, _ := m[key].(string)
	return s
}

// flowSummary résume un flux sur une ligne : déclencheur et étapes.
func flowSummary(f map[string]any) string {
	trig, _ := f["trigger"].(map[string]any)
	kind := str(trig, "kind")
	what := kind
	switch kind {
	case "schedule":
		s, _ := trig["schedule"].(map[string]any)
		what = "cron " + str(s, "cron")
	case "event":
		e, _ := trig["event"].(map[string]any)
		what = "événement " + str(e, "event")
	case "condition":
		c, _ := trig["condition"].(map[string]any)
		if t := str(c, "type"); t != "" {
			what = "si " + t
		} else {
			what = "conditions composées"
		}
	}
	steps, _ := f["steps"].([]any)
	var types []string
	for _, s := range steps {
		st, _ := s.(map[string]any)
		t := str(st, "type")
		if a, ok := st["action"].(map[string]any); ok {
			t = str(a, "type")
		}
		types = append(types, t)
	}
	return what + " → " + strings.Join(types, " → ")
}

func runAutomationFlows(action string) {
	switch action {
	case "list", "":
		_, args, client := autoArgs(4, "")
		path := "/api/v1/automation/flows"
		if t := flagValue(args, "-trigger", ""); t != "" {
			path += "?trigger=" + url.QueryEscape(t)
		}
		var flows []map[string]any
		call(client, "GET", path, nil, &flows, "flows list")
		if _, ok := args["-json"]; ok {
			printJSON(flows)
			return
		}
		if len(flows) == 0 {
			fmt.Println("(aucun flux)")
			return
		}
		for _, f := range flows {
			status := "✓"
			if en, _ := f["enabled"].(bool); !en {
				status = "✗"
			}
			origin, _ := f["origin"].(map[string]any)
			kind := str(origin, "kind")
			if tpl, _ := f["template"].(map[string]any); tpl["outdated"] == true {
				kind += ", modèle mis à jour"
			} else if tpl["missing"] == true {
				kind += ", modèle supprimé"
			}
			fmt.Printf("[%s] %-36s  %-28s %-6s %s  (%s)\n", status, str(f, "id"), str(f, "name"), str(f, "placement"), flowSummary(f), kind)
		}
	case "get":
		id, _, client := autoArgs(4, "goproxify automation flows get <id>")
		var f json.RawMessage
		call(client, "GET", "/api/v1/automation/flows/"+id, nil, &f, "flows get")
		printJSON(f)
	case "create":
		_, args, client := autoArgs(4, "")
		var f map[string]any
		call(client, "POST", "/api/v1/automation/flows", readJSONFile(flagValue(args, "-file", "")), &f, "flows create")
		fmt.Printf("Flux créé : %s (%s)\n", str(f, "id"), str(f, "placement"))
	case "update":
		id, args, client := autoArgs(4, "goproxify automation flows update <id> -file <flux.json>")
		var f map[string]any
		call(client, "PUT", "/api/v1/automation/flows/"+id, readJSONFile(flagValue(args, "-file", "")), &f, "flows update")
		fmt.Printf("Flux %s : version %v\n", id, f["version"])
	case "delete":
		id, args, client := autoArgs(4, "goproxify automation flows delete <id> [-y]")
		if _, yes := args["-y"]; !yes && !confirm("Supprimer le flux "+id+" ?") {
			return
		}
		call(client, "DELETE", "/api/v1/automation/flows/"+id, nil, nil, "flows delete")
		fmt.Println("Flux supprimé.")
	case "enable", "disable":
		id, _, client := autoArgs(4, "goproxify automation flows "+action+" <id>")
		call(client, "PATCH", "/api/v1/automation/flows/"+id, map[string]bool{"enabled": action == "enable"}, nil, "flows "+action)
		fmt.Printf("Flux %s : %s.\n", id, map[bool]string{true: "activé", false: "désactivé"}[action == "enable"])
	case "run":
		id, args, client := autoArgs(4, "goproxify automation flows run <id> [-dry-run] [-input k=v,…]")
		_, dry := args["-dry-run"]
		var res map[string]any
		call(client, "POST", "/api/v1/automation/flows/"+id+"/run", map[string]any{"dry_run": dry, "inputs": keyValues(flagValue(args, "-input", ""))}, &res, "flows run")
		printRunResult(res, dry)
	case "simulate":
		_, args, client := autoArgs(4, "")
		var res map[string]any
		call(client, "POST", "/api/v1/automation/simulate", map[string]any{"flow": readJSONFile(flagValue(args, "-file", "")), "inputs": keyValues(flagValue(args, "-input", ""))}, &res, "flows simulate")
		printRunResult(res, true)
	case "versions":
		id, _, client := autoArgs(4, "goproxify automation flows versions <id>")
		var vs []map[string]any
		call(client, "GET", "/api/v1/automation/flows/"+id+"/versions", nil, &vs, "flows versions")
		for _, v := range vs {
			f, _ := v["flow"].(map[string]any)
			fmt.Printf("v%-4v %s  %s  %s\n", v["version"], str(v, "created_at"), str(v, "created_by"), flowSummary(f))
			printChanges(v["changes"])
		}
	case "restore":
		id, _, client := autoArgs(4, "goproxify automation flows restore <id> <version>")
		version := subcommand(os.Args, 5)
		if version == "" {
			die("usage: goproxify automation flows restore <id> <version>")
		}
		var f map[string]any
		call(client, "POST", "/api/v1/automation/flows/"+id+"/versions/"+version+"/restore", nil, &f, "flows restore")
		fmt.Printf("Version %s rétablie (nouvelle version %v).\n", version, f["version"])
	case "detach":
		id, _, client := autoArgs(4, "goproxify automation flows detach <id>")
		call(client, "POST", "/api/v1/automation/flows/"+id+"/detach", nil, nil, "flows detach")
		fmt.Println("Flux détaché de son modèle : il se modifie maintenant comme un flux de l'éditeur.")
	case "params":
		id, args, client := autoArgs(4, "goproxify automation flows params <id> -set k=v,…")
		var cur map[string]any
		call(client, "GET", "/api/v1/automation/flows/"+id, nil, &cur, "flows get")
		origin, _ := cur["origin"].(map[string]any)
		params, _ := origin["params"].(map[string]any)
		if params == nil {
			params = map[string]any{}
		}
		for k, v := range keyValues(flagValue(args, "-set", "")) {
			params[k] = v
		}
		body := map[string]any{"name": flagValue(args, "-name", str(cur, "name")), "description": cur["description"], "enabled": cur["enabled"],
			"origin": map[string]any{"kind": "template", "params": params}}
		var f map[string]any
		call(client, "PUT", "/api/v1/automation/flows/"+id, body, &f, "flows params")
		fmt.Printf("Paramètres appliqués (version %v).\n", f["version"])
	default:
		die("action flows inconnue : %q\n%s", action, automationUsage)
	}
}

func printRunResult(res map[string]any, dry bool) {
	if matched, _ := res["matched"].(bool); !matched {
		fmt.Println("Condition fausse : rien ne s'exécute.")
		return
	}
	if !dry {
		fmt.Printf("Exécution lancée : %s\n", str(res, "run_id"))
		return
	}
	if sil, _ := res["silenced"].(bool); sil {
		fmt.Println("(en sourdine : un déclenchement automatique serait ignoré)")
	}
	trace, _ := res["trace"].([]any)
	for _, t := range trace {
		l, _ := t.(map[string]any)
		prefix := ""
		if f := str(l, "flow"); f != "" {
			prefix = "  [" + f + "] "
		}
		fmt.Printf("%s%-10s %-9s %-10s %s\n", prefix, str(l, "step_id"), str(l, "type"), str(l, "status"), str(l, "detail"))
	}
}

func runAutomationRuns(action string) {
	switch action {
	case "list", "":
		_, args, client := autoArgs(4, "")
		q := url.Values{}
		for flag, key := range map[string]string{"-flow": "flow_id", "-status": "status", "-limit": "limit"} {
			if v := flagValue(args, flag, ""); v != "" {
				q.Set(key, v)
			}
		}
		var runs []map[string]any
		call(client, "GET", "/api/v1/automation/runs?"+q.Encode(), nil, &runs, "runs list")
		if _, ok := args["-json"]; ok {
			printJSON(runs)
			return
		}
		if len(runs) == 0 {
			fmt.Println("(aucune exécution)")
			return
		}
		for _, r := range runs {
			fmt.Printf("%s  %-36s  %-17s %-24s %-18s %s\n", str(r, "started_at"), str(r, "id"), str(r, "status"), str(r, "flow_name"), str(r, "source"), str(r, "error"))
		}
	case "get":
		id, _, client := autoArgs(4, "goproxify automation runs get <run-id>")
		var r json.RawMessage
		call(client, "GET", "/api/v1/automation/runs/"+id, nil, &r, "runs get")
		printJSON(r)
	case "approve", "reject", "cancel":
		id, _, client := autoArgs(4, "goproxify automation runs "+action+" <run-id>")
		call(client, "POST", "/api/v1/automation/runs/"+id+"/"+action, nil, nil, "runs "+action)
		fmt.Println(map[string]string{"approve": "Approuvée.", "reject": "Refusée.", "cancel": "Annulée."}[action])
	case "replay":
		id, _, client := autoArgs(4, "goproxify automation runs replay <run-id>")
		var res map[string]any
		call(client, "POST", "/api/v1/automation/runs/"+id+"/replay", nil, &res, "runs replay")
		fmt.Printf("Nouvelle exécution : %s\n", str(res, "run_id"))
	default:
		die("action runs inconnue : %q", action)
	}
}

func runAutomationTemplates(action string) {
	switch action {
	case "list", "":
		_, _, client := autoArgs(4, "")
		var list []map[string]any
		call(client, "GET", "/api/v1/automation/templates", nil, &list, "templates list")
		sort.Slice(list, func(i, j int) bool {
			return str(list[i], "category")+str(list[i], "id") < str(list[j], "category")+str(list[j], "id")
		})
		for _, t := range list {
			var params []string
			ps, _ := t["params"].([]any)
			for _, p := range ps {
				pm, _ := p.(map[string]any)
				params = append(params, fmt.Sprintf("%s=%v", str(pm, "key"), pm["default"]))
			}
			fmt.Printf("%-12s %-30s %-9s %s  [%s]  installé %v fois\n", str(t, "category"), str(t, "id"), str(t, "kind"), str(t, "name"), strings.Join(params, ", "), t["installed"])
		}
	case "preview":
		id, args, client := autoArgs(4, "goproxify automation templates preview <id> [-set k=v,…] [-flow <id>]")
		var f map[string]any
		call(client, "POST", "/api/v1/automation/templates/"+id+"/preview",
			map[string]any{"params": keyValues(flagValue(args, "-set", "")), "flow_id": flagValue(args, "-flow", "")}, &f, "templates preview")
		fmt.Printf("%s (%s)\n%s\n", str(f, "name"), str(f, "placement"), flowSummary(f))
		if _, ok := f["changes"]; ok {
			fmt.Println("Changements à l'enregistrement :")
			printChanges(f["changes"])
		}
	case "install":
		id, args, client := autoArgs(4, "goproxify automation templates install <id> [-set k=v,…] [-name <nom>] [-disabled]")
		_, disabled := args["-disabled"]
		var f map[string]any
		call(client, "POST", "/api/v1/automation/templates/"+id+"/install",
			map[string]any{"name": flagValue(args, "-name", ""), "enabled": !disabled, "params": keyValues(flagValue(args, "-set", ""))}, &f, "templates install")
		fmt.Printf("Flux créé : %s — %s\n", str(f, "id"), str(f, "name"))
	default:
		die("action templates inconnue : %q", action)
	}
}

func runAutomationCatalog() {
	_, args, client := autoArgs(3, "")
	var c map[string]any
	call(client, "GET", "/api/v1/automation/catalog", nil, &c, "catalog")
	if _, ok := args["-json"]; ok {
		printJSON(c)
		return
	}
	for _, section := range []string{"triggers", "conditions", "actions", "steps"} {
		fmt.Printf("%s :\n", section)
		list, _ := c[section].([]any)
		for _, m := range list {
			mm, _ := m.(map[string]any)
			var keys []string
			fields, _ := mm["fields"].([]any)
			for _, f := range fields {
				fm, _ := f.(map[string]any)
				keys = append(keys, str(fm, "key"))
			}
			fmt.Printf("  %-20s %s  (%s)\n", str(mm, "type"), str(mm, "label"), strings.Join(keys, ", "))
		}
	}
	if metrics, _ := c["metrics"].([]any); len(metrics) > 0 {
		fmt.Println("métriques :")
		for _, m := range metrics {
			mm, _ := m.(map[string]any)
			edge := ""
			if b, _ := mm["edge"].(bool); b {
				edge = "  (aussi par chaque passerelle)"
			}
			fmt.Printf("  %-28s %s%s\n", str(mm, "key"), str(mm, "label"), edge)
		}
	}
}

func runAutomationSilences(action string) {
	switch action {
	case "list", "":
		_, _, client := autoArgs(4, "")
		var list []map[string]any
		call(client, "GET", "/api/v1/automation/silences", nil, &list, "silences list")
		if len(list) == 0 {
			fmt.Println("(aucune mise en sourdine)")
		}
		for _, s := range list {
			fmt.Printf("%s  %-24s %s → %s  %v\n", str(s, "id"), str(s, "name"), str(s, "starts_at"), str(s, "ends_at"), s["rule_ids"])
		}
	case "add":
		_, args, client := autoArgs(4, "")
		body := map[string]any{"name": flagValue(args, "-name", ""), "starts_at": flagValue(args, "-starts", ""), "ends_at": flagValue(args, "-ends", ""), "rule_ids": []string{}}
		if ids := flagValue(args, "-flows", ""); ids != "" {
			body["rule_ids"] = strings.Split(ids, ",")
		}
		var s map[string]any
		call(client, "POST", "/api/v1/automation/silences", body, &s, "silences add")
		fmt.Printf("Mise en sourdine créée : %s\n", str(s, "id"))
	case "delete":
		id, args, client := autoArgs(4, "goproxify automation silences delete <id> [-y]")
		if _, yes := args["-y"]; !yes && !confirm("Supprimer la mise en sourdine "+id+" ?") {
			return
		}
		call(client, "DELETE", "/api/v1/automation/silences/"+id, nil, nil, "silences delete")
		fmt.Println("Mise en sourdine supprimée.")
	default:
		die("action silences inconnue : %q", action)
	}
}

func runAutomationExport() {
	_, args, client := autoArgs(3, "")
	data, _, _, err := client.DoRaw("GET", "/api/v1/automation/export", nil, "", 200)
	if err != nil {
		die("export : %v", err)
	}
	out := flagValue(args, "-out", "")
	if out == "" {
		fmt.Print(string(data))
		return
	}
	if err := os.WriteFile(out, data, 0o600); err != nil {
		die("écriture fichier : %v", err)
	}
	fmt.Printf("Exporté vers %s\n", out)
}

func runAutomationImport() {
	_, args, client := autoArgs(3, "")
	file := flagValue(args, "-file", "")
	if file == "" {
		die("usage: goproxify automation import -file <automation.yaml>")
	}
	data, err := os.ReadFile(file)
	if err != nil {
		die("lecture fichier : %v", err)
	}
	res, _, _, err := client.DoRaw("POST", "/api/v1/automation/import", data, "application/x-yaml", 200)
	if err != nil {
		die("import : %v", err)
	}
	var s map[string]any
	_ = json.Unmarshal(res, &s)
	fmt.Printf("Flux : %v créés, %v mis à jour, %v refusés\n", s["flows_created"], s["flows_updated"], s["flows_rejected"])
	fmt.Printf("Canaux : %v créés, %v mis à jour — mises en sourdine : %v créées\n", s["channels_created"], s["channels_updated"], s["silences_created"])
	if errs, _ := s["errors"].([]any); len(errs) > 0 {
		for _, e := range errs {
			fmt.Printf("  ! %v\n", e)
		}
	}
}

// changeText décrit une différence entre deux versions d'un flux (champ changes de l'API).
func changeText(c map[string]any) string {
	step, detail := str(c, "step_id"), str(c, "detail")
	switch str(c, "kind") {
	case "created":
		return "création du flux"
	case "earliest_kept":
		return "plus ancienne version conservée"
	case "name":
		return "nom modifié"
	case "description":
		return "description modifiée"
	case "enabled":
		if detail == "true" {
			return "flux activé"
		}
		return "flux désactivé"
	case "trigger_kind":
		return "déclencheur remplacé (" + detail + ")"
	case "trigger":
		return "réglages du déclencheur modifiés"
	case "guard":
		return "garde-fou modifié (" + detail + ")"
	case "origin":
		return "origine modifiée (" + detail + ")"
	case "params":
		return "paramètres du modèle modifiés (" + detail + ")"
	case "step_added":
		return "étape " + step + " ajoutée : " + detail
	case "step_removed":
		return "étape " + step + " retirée : " + detail
	case "step_changed":
		return "étape " + step + " modifiée : " + detail
	case "step_moved":
		return "étape " + step + " déplacée : " + detail
	}
	return str(c, "kind")
}

func printChanges(v any) {
	list, _ := v.([]any)
	if len(list) == 0 {
		fmt.Println("      (aucun changement)")
	}
	for _, e := range list {
		c, _ := e.(map[string]any)
		fmt.Println("      - " + changeText(c))
	}
}
