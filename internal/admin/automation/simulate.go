// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"fmt"
)

// SimResult est le parcours simulé d'un flux : les conditions sont évaluées pour de vrai, aucune action
// n'est exécutée, les attentes sont sautées et les approbations supposées accordées.
type SimResult struct {
	Matched         bool           `json:"matched"`
	Detail          map[string]any `json:"detail,omitempty"`
	Trace           []StepLog      `json:"trace"`
	Silenced        bool           `json:"silenced,omitempty"`
	Placement       string         `json:"placement"`
	PlacementReason string         `json:"placement_reason,omitempty"`
}

// Simulate parcourt un flux, enregistré ou non (brouillon de l'éditeur). inputs tient lieu de détail pour
// un déclencheur manuel ou un événement.
func (s *Service) Simulate(ctx context.Context, f *Flow, inputs map[string]any) (*SimResult, error) {
	if f.ID != "" {
		if old, err := s.getFlow(ctx, f.ID); err == nil {
			keepSecrets(old, f)
		}
	} else {
		f.ID = "draft"
	}
	if err := s.check(ctx, f); err != nil {
		return nil, err
	}
	res := &SimResult{Trace: []StepLog{}}
	res.Placement, res.PlacementReason = placement(f)
	detail := normalizeJSON(inputs)
	switch f.Trigger.Kind {
	case TriggerCondition:
		matched, d, err := s.evalCond(ctx, f.Trigger.Condition, flowScope(f))
		if err != nil {
			return nil, invalid("condition : %v", err)
		}
		if !matched {
			return res, nil
		}
		detail = d
	case TriggerManual:
		d, err := applyInputs(f, detail)
		if err != nil {
			return nil, err
		}
		detail = d
	case TriggerSchedule:
		detail["scheduled_at"] = s.now().Format("2006-01-02T15:04:05Z07:00")
	}
	res.Matched, res.Detail = true, detail
	res.Silenced = s.silenced(ctx, f.ID)
	run := &Run{ID: "simulation", FlowID: f.ID, FlowName: f.Name, Context: RunContext{Detail: detail, Steps: map[string]map[string]any{}}}
	s.simulateSteps(ctx, run, f.Steps, "", 0, &res.Trace)
	return res, nil
}

// simulateSteps retourne false quand une étape « arrêter » termine le parcours.
func (s *Service) simulateSteps(ctx context.Context, r *Run, steps []Step, flowName string, depth int, trace *[]StepLog) bool {
	for i := range steps {
		st := &steps[i]
		scope := runScope(r)
		l := StepLog{StepID: st.ID, Type: st.Type, Status: "simulated", Flow: flowName, StartedAt: s.now()}
		switch st.Type {
		case StepAction:
			if _, man, ok := actionRegistry.Lookup(st.Action.Type); ok {
				l.Output = man.Mask(resolveMap(st.Action.Config, scope))
				l.Detail = man.Label
			}
			r.Context.Steps[st.ID] = map[string]any{"ok": true}
		case StepIf:
			matched, d, err := s.evalCond(ctx, st.Condition, scope)
			out := map[string]any{"matched": matched}
			for k, v := range d {
				out[k] = v
			}
			r.Context.Steps[st.ID] = out
			l.Status, l.Output = "done", out
			if err != nil {
				l.Status, l.Detail = "failed", err.Error()
				*trace = append(*trace, l)
				if st.OnError != "continue" {
					return false
				}
				continue
			}
			l.Detail = "branche alors"
			branch := st.Then
			if !matched {
				l.Detail, branch = "branche sinon", st.Else
			}
			*trace = append(*trace, l)
			if !s.simulateSteps(ctx, r, branch, flowName, depth, trace) {
				return false
			}
			continue
		case StepWait:
			l.Status, l.Detail = "skipped", "attente de "+cfgStr(resolveMap(st.Config, scope), "duration")+" non simulée"
		case StepApproval:
			l.Status, l.Detail = "approved", cfgStr(resolveMap(st.Config, scope), "message")
			r.Context.Steps[st.ID] = map[string]any{"decision": "approved", "actor": "simulation"}
		case StepCall:
			cfg := resolveMap(st.Config, scope)
			target, err := s.getFlow(ctx, cfgStr(cfg, "flow_id"))
			if err != nil {
				l.Status, l.Detail = "failed", "playbook introuvable"
				*trace = append(*trace, l)
				return false
			}
			l.Detail = "lance " + target.Name
			*trace = append(*trace, l)
			inputs, _ := cfg["inputs"].(map[string]any)
			childDetail, _ := applyInputs(target, inputs)
			child := &Run{ID: "simulation", FlowID: target.ID, FlowName: target.Name, Context: RunContext{Detail: childDetail, Steps: map[string]map[string]any{}}}
			if depth+1 > maxDepth {
				*trace = append(*trace, StepLog{StepID: st.ID, Type: st.Type, Status: "failed", Detail: "appels trop profonds", Flow: target.Name})
				return false
			}
			s.simulateSteps(ctx, child, target.Steps, target.Name, depth+1, trace)
			r.Context.Steps[st.ID] = map[string]any{"status": string(RunCompleted)}
			continue
		case StepStop:
			cfg := resolveMap(st.Config, scope)
			l.Status, l.Detail = "done", fmt.Sprintf("arrêt (%s) %s", cfgStr(cfg, "status"), cfgStr(cfg, "reason"))
			*trace = append(*trace, l)
			return false
		}
		*trace = append(*trace, l)
	}
	return true
}
