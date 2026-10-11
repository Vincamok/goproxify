// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"github.com/vincamok/goproxify/internal/modules"
)

// stepManifests décrivent la configuration (Step.Config) de chaque type d'étape. L'étape « action » porte sa
// brique dans Step.Action, l'étape « si » sa condition dans Step.Condition : leur Config reste vide.
var stepManifests = []modules.Manifest{
	{Type: StepAction, Label: "Action", Fields: []modules.Field{}, Attrs: map[string]any{"category": "action"}},
	{Type: StepIf, Label: "Si / sinon", Fields: []modules.Field{}, Attrs: map[string]any{"category": "logic"}},
	{Type: StepWait, Label: "Attendre", Attrs: map[string]any{"category": "logic"}, Fields: []modules.Field{
		{Key: "duration", Label: "Durée", Kind: modules.KindDuration, Required: true, Default: "5m"},
	}},
	{Type: StepApproval, Label: "Approbation", Attrs: map[string]any{"category": "logic", "outputs": []string{"decision", "actor"}}, Fields: []modules.Field{
		{Key: "message", Label: "Question posée", Kind: modules.KindText, Placeholder: "Désactiver {{detail.proxy_name}} ?"},
		{Key: "timeout", Label: "Délai de décision (vide = sans limite)", Kind: modules.KindDuration},
		{Key: "on_timeout", Label: "Sans décision dans le délai", Kind: modules.KindSelect, Default: "reject", Options: []modules.Option{
			{Value: "reject", Label: "Refuser"}, {Value: "approve", Label: "Approuver"}}},
	}},
	{Type: StepCall, Label: "Lancer un playbook", Attrs: map[string]any{"category": "logic", "outputs": []string{"run_id", "status"}}, Fields: []modules.Field{
		{Key: "flow_id", Label: "Playbook", Kind: modules.KindSelect, Source: "flows:manual", Required: true},
		{Key: "wait", Label: "Attendre sa fin", Kind: modules.KindBool, Default: true},
	}},
	{Type: StepStop, Label: "Arrêter", Attrs: map[string]any{"category": "logic"}, Fields: []modules.Field{
		{Key: "status", Label: "Statut final", Kind: modules.KindSelect, Default: "stopped", Options: []modules.Option{
			{Value: "stopped", Label: "Arrêté"}, {Value: "completed", Label: "Terminé"}, {Value: "failed", Label: "Échec"}}},
		{Key: "reason", Label: "Raison", Kind: modules.KindText},
	}},
}

func stepManifest(typ string) (modules.Manifest, bool) {
	for _, m := range stepManifests {
		if m.Type == typ {
			return m, true
		}
	}
	return modules.Manifest{}, false
}

// triggerManifests décrivent les déclencheurs. Le déclencheur « condition » porte son arbre dans
// Trigger.Condition ; ses champs ici sont ceux du déclencheur lui-même.
var triggerManifests = []modules.Manifest{
	{Type: string(TriggerCondition), Label: "Condition surveillée", Attrs: map[string]any{"tab": "rules"}, Fields: []modules.Field{
		{Key: "interval_sec", Label: "Vérifier toutes les (secondes)", Kind: modules.KindNumber, Default: 60, Help: "Minimum 30 s."},
	}},
	{Type: string(TriggerEvent), Label: "Événement", Attrs: map[string]any{"tab": "rules"}, Fields: []modules.Field{
		{Key: "event", Label: "Événement", Kind: modules.KindSelect, Source: "events", Required: true},
		{Key: "nodes", Label: "Nœuds (vide = tous)", Kind: modules.KindList},
		{Key: "domain_glob", Label: "Domaine (motif, ex. *.prod.fr)", Kind: modules.KindText},
		{Key: "min_severity", Label: "Gravité minimale", Kind: modules.KindSelect, Options: []modules.Option{
			{Value: "info", Label: "Info"}, {Value: "warning", Label: "Avertissement"}, {Value: "critical", Label: "Critique"}}},
	}},
	{Type: string(TriggerSchedule), Label: "Horaire (cron)", Attrs: map[string]any{"tab": "schedules"}, Fields: []modules.Field{
		{Key: "cron", Label: "Expression cron", Kind: modules.KindText, Required: true, Default: "0 3 * * *",
			Help: "minute heure jour mois jour-de-semaine, à l'heure de l'Admin"},
	}},
	{Type: string(TriggerManual), Label: "Manuel (playbook)", Attrs: map[string]any{"tab": "playbooks"}, Fields: []modules.Field{}},
}
