// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"time"

	"github.com/google/uuid"
	edgere "github.com/vincamok/goproxify/internal/edge/rulesengine"
	edgews "github.com/vincamok/goproxify/internal/edge/ws"
)

// Un flux simple — une condition que la passerelle sait évaluer sur ses données, puis une action qu'elle
// sait exécuter — tourne sur chaque passerelle, qui en garde une copie locale chiffrée (ADR 0006) : il
// continue pendant une coupure de l'Admin. L'Admin ne l'évalue plus lui-même, sans quoi l'action aurait
// lieu deux fois. Tout le reste (attente, approbation, si/sinon, appels, conditions de l'Admin) tourne sur
// l'Admin.

// edgeDefaults sont les valeurs qu'une passerelle applique d'elle-même quand le champ est vide.
var edgeDefaults = map[string]map[string]string{
	"ban_ip":        {"ip": "{{detail.ip}}"},
	"disable_proxy": {"proxy_id": "{{detail.proxy_id}}"},
}

// placement indique où un flux s'exécute, et pourquoi pas sur les passerelles.
func placement(f *Flow) (string, string) {
	if f.Guard.Placement == PlacementAdmin {
		return PlacementAdmin, "exécution forcée sur l'Admin"
	}
	if f.Trigger.Kind != TriggerCondition || f.Trigger.Condition == nil {
		return PlacementAdmin, "seuls les flux à condition s'exécutent sur les passerelles"
	}
	c := f.Trigger.Condition
	if c.Type == "" {
		return PlacementAdmin, "condition composée (et / ou / non)"
	}
	if _, man, ok := condRegistry.Lookup(c.Type); !ok || !attrBool(man.Attrs, "edge") {
		return PlacementAdmin, "condition évaluée sur les données de l'Admin"
	}
	if len(f.Steps) != 1 || f.Steps[0].Type != StepAction || f.Steps[0].Action == nil {
		return PlacementAdmin, "plusieurs étapes, ou étape autre qu'une action"
	}
	a := f.Steps[0].Action
	if _, man, ok := actionRegistry.Lookup(a.Type); !ok || !attrBool(man.Attrs, "edge") {
		return PlacementAdmin, "action exécutée par l'Admin"
	}
	for k, v := range a.Config {
		s, isStr := v.(string)
		if !isStr || !isVar(s) {
			continue
		}
		if edgeDefaults[a.Type][k] != s {
			return PlacementAdmin, "variable que la passerelle ne sait pas résoudre"
		}
	}
	if f.Guard.CooldownKey != "" {
		return PlacementAdmin, "délai minimum par valeur"
	}
	if hasVars(c.Config) {
		return PlacementAdmin, "variable dans la condition"
	}
	return PlacementEdge, ""
}

func attrBool(attrs map[string]any, key string) bool {
	b, _ := attrs[key].(bool)
	return b
}

func hasVars(m map[string]any) bool { return len(varsIn(m)) > 0 }

// EdgeRules traduit les flux exécutés par les passerelles dans leur format de règle.
func (s *Service) EdgeRules(ctx context.Context) ([]edgere.Rule, error) {
	flows, err := s.queryFlows(ctx, `WHERE f.trigger_kind=?`, string(TriggerCondition))
	if err != nil {
		return nil, err
	}
	out := []edgere.Rule{}
	for _, f := range flows {
		if p, _ := placement(f); p != PlacementEdge {
			continue
		}
		var cond edgere.Condition
		copyJSON(f.Trigger.Condition.Config, &cond)
		cond.Type = edgere.ConditionType(f.Trigger.Condition.Type)
		cfg := map[string]any{}
		for k, v := range f.Steps[0].Action.Config {
			if s, ok := v.(string); ok && isVar(s) {
				continue
			}
			cfg[k] = v
		}
		var act edgere.Action
		copyJSON(cfg, &act)
		act.Type = edgere.ActionType(f.Steps[0].Action.Type)
		cooldown := int(cooldownOf(f) / time.Second)
		out = append(out, edgere.Rule{ID: f.ID, Name: f.Name, Description: f.Description, Enabled: f.Enabled,
			Condition: cond, Action: act, CooldownSec: cooldown, CreatedAt: f.CreatedAt, UpdatedAt: f.UpdatedAt})
	}
	return out, nil
}

// RecordEdgeFired journalise un déclenchement remonté par une passerelle, et achemine sa notification : la
// passerelle n'a pas de canaux, l'Admin publie l'événement automation_notify avec le message du flux.
func (s *Service) RecordEdgeFired(p edgews.RuleFiredPayload) {
	if p.RuleID == "" || !p.CondResult {
		return
	}
	ctx := context.Background()
	f, err := s.getFlow(ctx, p.RuleID)
	if err != nil {
		return
	}
	now := s.now()
	status, errMsg := RunCompleted, p.Error
	if !p.ActionTaken {
		status = RunFailed
	}
	node := p.NodeName
	if node == "" {
		node = "passerelle"
	}
	r := &Run{ID: uuid.NewString(), FlowID: f.ID, FlowName: f.Name, FlowVersion: f.Version, Source: "edge:" + node,
		TriggerKind: f.Trigger.Kind, Status: status, Error: errMsg, StartedAt: now, FinishedAt: &now,
		Context: RunContext{Detail: p.Detail, Steps: map[string]map[string]any{}}, definition: f.definition()}
	if r.Context.Detail == nil {
		r.Context.Detail = map[string]any{}
	}
	if err := s.insertRun(ctx, r); err != nil {
		s.log.Warn("automation: déclenchement de passerelle non journalisé", "flow", f.Name, "err", err)
		return
	}
	stepID, typ := "", p.ActionType
	if len(f.Steps) > 0 {
		stepID = f.Steps[0].ID
	}
	l := StepLog{StepID: stepID, Type: StepAction, Status: "done", Detail: typ + " sur " + node, StartedAt: now}
	if !p.ActionTaken {
		l.Status, l.Detail = "failed", p.Error
	}
	s.logStep(r.ID, l)
	s.recordFired(f.ID, r.ID, status, true)
	if p.ActionType == "notify" && p.ActionTaken && len(f.Steps) > 0 && f.Steps[0].Action != nil {
		scope := map[string]any{"detail": r.Context.Detail, "flow": map[string]any{"id": f.ID, "name": f.Name}}
		cfg := resolveMap(f.Steps[0].Action.Config, scope)
		msg := cfgStr(cfg, "notify_message")
		if msg == "" {
			msg = "Flux déclenché sur " + node + " : " + f.Name
		}
		detail := map[string]any{"node_name": node}
		for k, v := range r.Context.Detail {
			detail[k] = v
		}
		s.emitNotify(f.ID, f.Name, cfgStr(cfg, "notify_severity"), msg, detail, nil)
	}
}
