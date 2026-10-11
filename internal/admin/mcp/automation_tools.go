// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"

	adminauth "github.com/vincamok/goproxify/internal/admin/auth"
	"github.com/vincamok/goproxify/internal/admin/automation"
)

// Outils des flux d'automatisation : mêmes opérations que /api/v1/automation (automation.Service).
func automationTools() []map[string]any {
	flowDoc := "Flux JSON : {name, description, enabled, trigger:{kind: condition|event|schedule|manual, condition:{type, config} | {all|any:[…]} | {not:…}, " +
		"event:{event, nodes, domain_glob, min_severity, match}, schedule:{cron}, manual:{inputs:[champs]}}, guard:{cooldown_sec, cooldown_key, max_concurrent, placement}, " +
		"steps:[{id, type: action|wait|if|approval|call|stop, action:{type, config}, condition:{…}, then:[…], else:[…], config:{…}, on_error: stop|continue}]}. " +
		"Types et champs : get_automation_catalog. Variables : {{detail.x}}, {{steps.<id>.x}}, {{flow.name}}."
	return []map[string]any{
		{"name": "list_flows", "description": "Liste les flux d'automatisation : règles (déclencheur condition ou événement), planifications (schedule) et playbooks (manual), avec leur état (template.outdated : modèle changé depuis l'installation ; déclenchements, prochaine exécution, attentes) et où ils s'exécutent (Admin ou passerelles).",
			"inputSchema": schema(opt("trigger", "string", "Filtre : condition, event, schedule, manual (plusieurs séparés par des virgules)"))},
		{"name": "get_flow", "description": "Détail d'un flux (secrets masqués).", "inputSchema": schema(req("id", "string", "ID du flux"))},
		{"name": "create_flow", "description": "Crée un flux. " + flowDoc, "inputSchema": schema(req("flow", "object", "Le flux"))},
		{"name": "update_flow", "description": "Remplace la définition d'un flux construit dans l'éditeur (un flux issu d'un modèle se modifie avec update_flow_params). Les secrets renvoyés masqués sont conservés. " + flowDoc,
			"inputSchema": schema(req("id", "string", "ID du flux"), req("flow", "object", "Le flux complet"))},
		{"name": "set_flow_enabled", "description": "Active ou désactive un flux.",
			"inputSchema": schema(req("id", "string", "ID du flux"), req("enabled", "boolean", "true pour activer"))},
		{"name": "delete_flow", "description": "Supprime un flux (refusé s'il est appelé par un autre).", "inputSchema": schema(req("id", "string", "ID du flux"))},
		{"name": "run_flow", "description": "Lance un flux à la main (sans garde-fous). Un flux à condition l'évalue d'abord. Avec dry_run, simule sans agir.",
			"inputSchema": schema(req("id", "string", "ID du flux"), opt("inputs", "object", "Paramètres (playbook) ou détail"), opt("dry_run", "boolean", "Simuler sans agir"))},
		{"name": "simulate_flow", "description": "Simule un flux non enregistré : conditions évaluées pour de vrai, actions jamais exécutées. " + flowDoc,
			"inputSchema": schema(req("flow", "object", "Le flux à simuler"), opt("inputs", "object", "Détail ou paramètres"))},
		{"name": "list_flow_versions", "description": "Historique des versions d'un flux (20 dernières), chacune avec ses changements par rapport à la précédente (changes : kind, step_id, detail).", "inputSchema": schema(req("id", "string", "ID du flux"))},
		{"name": "restore_flow_version", "description": "Rétablit une version d'un flux (crée une nouvelle version).",
			"inputSchema": schema(req("id", "string", "ID du flux"), req("version", "number", "Version à rétablir"))},
		{"name": "detach_flow", "description": "Détache un flux de son modèle : il devient modifiable dans l'éditeur.", "inputSchema": schema(req("id", "string", "ID du flux"))},
		{"name": "update_flow_params", "description": "Modifie les paramètres d'un flux issu d'un modèle (le flux est reconstruit).",
			"inputSchema": schema(req("id", "string", "ID du flux"), req("params", "object", "Paramètres du modèle"), opt("name", "string", "Nom"), opt("enabled", "boolean", "Activé (défaut : inchangé)"))},
		{"name": "list_flow_runs", "description": "Liste les exécutions de flux (journal) : statut, source (admin, edge:<nœud>, manual:<acteur>, call:<run>), erreurs. status=waiting_approval liste les approbations en attente.",
			"inputSchema": schema(opt("flow_id", "string", "ID du flux"), opt("status", "string", "Statuts séparés par des virgules"), opt("limit", "number", "Nombre (défaut 100, max 500)"))},
		{"name": "get_flow_run", "description": "Détail d'une exécution et journal de ses étapes.", "inputSchema": schema(req("run_id", "string", "ID de l'exécution"))},
		{"name": "decide_flow_run", "description": "Approuve ou refuse une exécution en attente d'approbation.",
			"inputSchema": schema(req("run_id", "string", "ID de l'exécution"), req("approve", "boolean", "true pour approuver"))},
		{"name": "cancel_flow_run", "description": "Annule une exécution en cours ou en attente.", "inputSchema": schema(req("run_id", "string", "ID de l'exécution"))},
		{"name": "replay_flow_run", "description": "Relance un flux avec le détail d'une exécution terminée (interrompue, en échec…).", "inputSchema": schema(req("run_id", "string", "ID de l'exécution"))},
		{"name": "get_automation_catalog", "description": "Catalogue des briques : déclencheurs, événements, conditions, actions, types d'étape (avec leurs champs) et métriques disponibles.", "inputSchema": schema()},
		{"name": "list_flow_templates", "description": "Liste les modèles de flux et leurs paramètres.", "inputSchema": schema()},
		{"name": "install_flow_template", "description": "Crée un flux depuis un modèle.",
			"inputSchema": schema(req("template_id", "string", "ID du modèle"), opt("params", "object", "Paramètres (défauts sinon)"), opt("name", "string", "Nom du flux"), opt("enabled", "boolean", "Activer (défaut true)"))},
		{"name": "list_silences", "description": "Liste les mises en sourdine (flux et règles d'alerte).", "inputSchema": schema()},
		{"name": "create_silence", "description": "Met en sourdine des flux et/ou des règles de routage d'alertes sur une période (vide = tout).",
			"inputSchema": schema(req("name", "string", "Nom"), req("starts_at", "string", "Début (RFC3339)"), req("ends_at", "string", "Fin (RFC3339)"),
				opt("rule_ids", "array", "IDs de flux (list_flows) et/ou de règles d'alerte (list_alert_rules) ; vide = tout"))},
		{"name": "delete_silence", "description": "Supprime une mise en sourdine.", "inputSchema": schema(req("id", "string", "ID"))},
		{"name": "export_automation", "description": "Exporte en YAML les flux, canaux d'alerte et mises en sourdine (secrets masqués), réimportable tel quel.", "inputSchema": schema()},
		{"name": "import_automation", "description": "Importe un document YAML au format d'export_automation : flux et canaux mis à jour par nom ou créés, mises en sourdine ajoutées.",
			"inputSchema": schema(req("yaml", "string", "Document YAML"))},
	}
}

func init() { tools = append(tools, automationTools()...) }

func objArg(args map[string]any, key string) map[string]any {
	m, _ := args[key].(map[string]any)
	return m
}

func flowArg(args map[string]any) (*automation.Flow, error) {
	m := objArg(args, "flow")
	if m == nil {
		return nil, fmt.Errorf("flow requis (objet)")
	}
	b, _ := json.Marshal(m)
	var f automation.Flow
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, fmt.Errorf("flow illisible : %w", err)
	}
	return &f, nil
}

// callAutomationTool exécute un outil de flux ; ok est faux si name n'en est pas un.
func (h *Handler) callAutomationTool(r *http.Request, name string, args map[string]any) (result any, err error, ok bool) {
	switch name {
	case "list_flows", "get_flow", "create_flow", "update_flow", "set_flow_enabled", "delete_flow", "run_flow", "simulate_flow",
		"list_flow_versions", "restore_flow_version", "detach_flow", "update_flow_params", "list_flow_runs", "get_flow_run",
		"decide_flow_run", "cancel_flow_run", "replay_flow_run", "get_automation_catalog", "list_flow_templates",
		"install_flow_template", "list_silences", "create_silence", "delete_silence", "export_automation", "import_automation":
	default:
		return nil, nil, false
	}
	if h.Automation == nil {
		return nil, fmt.Errorf("flux d'automatisation non disponibles"), true
	}
	result, err = h.automationTool(r, name, args)
	return result, err, true
}

func (h *Handler) automationTool(r *http.Request, name string, args map[string]any) (any, error) {
	ctx, svc := r.Context(), h.Automation
	actor := svc.ActorLabel(ctx, adminauth.UserIDFromContext(ctx), adminauth.ActorFromContext(ctx))
	id := argStr(args, "id")
	runID := argStr(args, "run_id")
	switch name {
	case "list_flows":
		var kinds []automation.TriggerKind
		for _, k := range strings.Split(argStr(args, "trigger"), ",") {
			if k = strings.TrimSpace(k); k != "" {
				kinds = append(kinds, automation.TriggerKind(k))
			}
		}
		return svc.List(ctx, kinds...)
	case "get_flow":
		return svc.Get(ctx, id)
	case "create_flow":
		f, err := flowArg(args)
		if err != nil {
			return nil, err
		}
		return svc.Create(ctx, f, actor)
	case "update_flow":
		f, err := flowArg(args)
		if err != nil {
			return nil, err
		}
		return svc.Update(ctx, id, f, actor)
	case "set_flow_enabled":
		enabled, _ := args["enabled"].(bool)
		return svc.SetEnabled(ctx, id, enabled)
	case "delete_flow":
		return map[string]bool{"ok": true}, svc.Delete(ctx, id)
	case "run_flow":
		if dry, _ := args["dry_run"].(bool); dry {
			f, err := svc.Get(ctx, id)
			if err != nil {
				return nil, err
			}
			return svc.Simulate(ctx, f, objArg(args, "inputs"))
		}
		return svc.RunNow(ctx, id, objArg(args, "inputs"), actor)
	case "simulate_flow":
		f, err := flowArg(args)
		if err != nil {
			return nil, err
		}
		return svc.Simulate(ctx, f, objArg(args, "inputs"))
	case "list_flow_versions":
		return svc.Versions(ctx, id)
	case "restore_flow_version":
		v, _ := args["version"].(float64)
		return svc.Restore(ctx, id, int(v), actor)
	case "detach_flow":
		return svc.Detach(ctx, id, actor)
	case "update_flow_params":
		cur, err := svc.Get(ctx, id)
		if err != nil {
			return nil, err
		}
		u := automation.TemplateUpdate{Name: cur.Name, Description: cur.Description, Enabled: cur.Enabled, Params: objArg(args, "params")}
		if n := argStr(args, "name"); n != "" {
			u.Name = n
		}
		if en, ok := args["enabled"].(bool); ok {
			u.Enabled = en
		}
		return svc.UpdateParams(ctx, id, u, actor)
	case "list_flow_runs":
		f := automation.RunFilter{FlowID: argStr(args, "flow_id")}
		for _, st := range strings.Split(argStr(args, "status"), ",") {
			if st = strings.TrimSpace(st); st != "" {
				f.Status = append(f.Status, automation.RunStatus(st))
			}
		}
		if n, ok := args["limit"].(float64); ok {
			f.Limit = int(n)
		}
		return svc.Runs(ctx, f)
	case "get_flow_run":
		return svc.GetRun(ctx, runID)
	case "decide_flow_run":
		approve, _ := args["approve"].(bool)
		return map[string]bool{"ok": true}, svc.Decide(ctx, runID, approve, actor)
	case "cancel_flow_run":
		return map[string]bool{"ok": true}, svc.Cancel(ctx, runID, actor)
	case "replay_flow_run":
		return svc.Replay(ctx, runID, actor)
	case "get_automation_catalog":
		return svc.Catalog(), nil
	case "list_flow_templates":
		return svc.ListTemplates(ctx)
	case "install_flow_template":
		u := automation.TemplateUpdate{Name: argStr(args, "name"), Enabled: true, Params: objArg(args, "params")}
		if en, ok := args["enabled"].(bool); ok {
			u.Enabled = en
		}
		return svc.Install(ctx, argStr(args, "template_id"), u, actor)
	case "list_silences":
		return svc.Silences(ctx)
	case "create_silence":
		starts, err1 := time.Parse(time.RFC3339, argStr(args, "starts_at"))
		ends, err2 := time.Parse(time.RFC3339, argStr(args, "ends_at"))
		if err1 != nil || err2 != nil {
			return nil, fmt.Errorf("starts_at et ends_at au format RFC3339")
		}
		return svc.CreateSilence(ctx, automation.Silence{Name: argStr(args, "name"), RuleIDs: argStringSlice(args, "rule_ids"), StartsAt: starts, EndsAt: ends})
	case "delete_silence":
		return map[string]bool{"ok": true}, svc.DeleteSilence(ctx, id)
	case "export_automation":
		data, err := svc.Export(ctx)
		if err != nil {
			return nil, err
		}
		return map[string]string{"yaml": string(data)}, nil
	case "import_automation":
		return svc.Import(ctx, []byte(argStr(args, "yaml")), actor)
	}
	return nil, fmt.Errorf("outil inconnu : %s", name)
}
