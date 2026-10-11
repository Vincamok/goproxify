// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"fmt"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/adminmetrics"
	"github.com/vincamok/goproxify/internal/sqltime"
)

const actionTimeout = 30 * time.Second

// stepPos situe une étape : sa liste, sa position, et le « si » qui la contient.
type stepPos struct {
	step   *Step
	list   []Step
	i      int
	parent string
}

type stepIndex map[string]stepPos

func indexSteps(steps []Step) stepIndex {
	ix := stepIndex{}
	var walk func(list []Step, parent string)
	walk = func(list []Step, parent string) {
		for i := range list {
			ix[list[i].ID] = stepPos{step: &list[i], list: list, i: i, parent: parent}
			walk(list[i].Then, list[i].ID)
			walk(list[i].Else, list[i].ID)
		}
	}
	walk(steps, "")
	return ix
}

// after retourne l'étape qui suit id : la suivante de sa liste, sinon celle qui suit le « si » parent.
func (ix stepIndex) after(id string) string {
	p, ok := ix[id]
	if !ok {
		return ""
	}
	if p.i+1 < len(p.list) {
		return p.list[p.i+1].ID
	}
	if p.parent != "" {
		return ix.after(p.parent)
	}
	return ""
}

func firstID(steps []Step) string {
	if len(steps) == 0 {
		return ""
	}
	return steps[0].ID
}

// startRun enregistre une exécution et la lance en arrière-plan.
func (s *Service) startRun(ctx context.Context, f *Flow, o fireOpts) (*Run, error) {
	detail := o.detail
	if detail == nil {
		detail = map[string]any{}
	}
	source := o.source
	if source == "" {
		source = "admin"
	}
	r := &Run{
		ID: uuid.NewString(), FlowID: f.ID, FlowName: f.Name, FlowVersion: f.Version, Source: source,
		TriggerKind: f.Trigger.Kind, Status: RunRunning, Cursor: firstID(f.Steps),
		Context:     RunContext{Detail: detail, Steps: map[string]map[string]any{}, Chain: o.chain},
		ParentRunID: o.parentRunID, ParentStepID: o.parentStepID, Depth: o.depth,
		StartedAt: s.now(), definition: f.definition(),
	}
	if err := s.insertRun(ctx, r); err != nil {
		return nil, err
	}
	s.recordFired(f.ID, r.ID, RunRunning, true)
	s.inflight.Add(1)
	go func() {
		defer s.inflight.Done()
		s.advance(r)
	}()
	return r, nil
}

// advance exécute les étapes à partir du curseur, jusqu'à une suspension (attente, approbation, appel) ou
// la fin. L'état est enregistré après chaque étape.
func (s *Service) advance(r *Run) {
	ctx := context.Background()
	ix := indexSteps(r.definition.Steps)
	for r.Cursor != "" {
		if s.cancelled(r.ID) {
			return
		}
		pos, ok := ix[r.Cursor]
		if !ok {
			s.finish(r, RunFailed, fmt.Sprintf("étape %q introuvable", r.Cursor))
			return
		}
		st := pos.step
		scope := runScope(r)
		started := s.now()
		switch st.Type {
		case StepAction:
			out, err := s.runAction(ctx, r, st, scope)
			if !s.stepDone(r, st, started, out, err, ix) {
				return
			}
		case StepIf:
			matched, detail, err := s.evalCond(ctx, st.Condition, scope)
			if err != nil {
				if !s.stepDone(r, st, started, nil, err, ix) {
					return
				}
				continue
			}
			out := map[string]any{"matched": matched}
			for k, v := range detail {
				out[k] = v
			}
			r.Context.Steps[st.ID] = out
			branch := "alors"
			next := firstID(st.Then)
			if !matched {
				branch, next = "sinon", firstID(st.Else)
			}
			if next == "" {
				next = ix.after(st.ID)
			}
			s.logStep(r.ID, StepLog{StepID: st.ID, Type: st.Type, Status: "done", Detail: "branche " + branch, Output: out, StartedAt: started})
			r.Cursor = next
			s.saveRun(r)
		case StepWait:
			d, _, err := cfgDur(resolveMap(st.Config, scope), "duration", "")
			if err != nil {
				if !s.stepDone(r, st, started, nil, err, ix) {
					return
				}
				continue
			}
			at := s.now().Add(d)
			s.logStep(r.ID, StepLog{StepID: st.ID, Type: st.Type, Status: "done", Detail: "attente jusqu'à " + at.Format("15:04:05"), StartedAt: started})
			r.Status, r.ResumeAt, r.Cursor = RunWaiting, &at, ix.after(st.ID)
			s.saveRun(r)
			return
		case StepApproval:
			s.suspendApproval(r, st, scope, started)
			return
		case StepCall:
			if !s.runCall(ctx, r, st, scope, started, ix) {
				return
			}
		case StepStop:
			cfg := resolveMap(st.Config, scope)
			status := RunStatus(cfgStr(cfg, "status"))
			if status != RunCompleted && status != RunFailed {
				status = RunStopped
			}
			s.logStep(r.ID, StepLog{StepID: st.ID, Type: st.Type, Status: "done", Detail: cfgStr(cfg, "reason"), StartedAt: started})
			s.finish(r, status, cfgStr(cfg, "reason"))
			return
		default:
			s.finish(r, RunFailed, fmt.Sprintf("type d'étape %q inconnu", st.Type))
			return
		}
	}
	s.finish(r, RunCompleted, "")
}

// stepDone journalise une étape terminée et avance le curseur. Retourne false si l'exécution s'arrête
// (erreur sans « continuer »).
func (s *Service) stepDone(r *Run, st *Step, started time.Time, out map[string]any, err error, ix stepIndex) bool {
	if out == nil {
		out = map[string]any{}
	}
	out["ok"] = err == nil
	l := StepLog{StepID: st.ID, Type: st.Type, Status: "done", Output: out, StartedAt: started}
	if err != nil {
		out["error"] = err.Error()
		l.Status, l.Detail = "failed", err.Error()
	}
	s.logStep(r.ID, l)
	r.Context.Steps[st.ID] = out
	if err != nil && st.OnError != "continue" {
		s.finish(r, RunFailed, fmt.Sprintf("étape %s : %v", st.ID, err))
		return false
	}
	r.Cursor = ix.after(st.ID)
	s.saveRun(r)
	return true
}

func (s *Service) logStep(runID string, l StepLog) {
	now := s.now()
	l.FinishedAt = &now
	s.appendStep(runID, l)
}

func (s *Service) runAction(ctx context.Context, r *Run, st *Step, scope map[string]any) (map[string]any, error) {
	if st.Action == nil {
		return nil, fmt.Errorf("action absente")
	}
	mod, _, ok := actionRegistry.Lookup(st.Action.Type)
	if !ok {
		return nil, fmt.Errorf("action inconnue : %q", st.Action.Type)
	}
	actx, cancel := context.WithTimeout(ctx, actionTimeout)
	defer cancel()
	description := ""
	if f, err := s.getFlow(ctx, r.FlowID); err == nil {
		description = f.Description
	}
	out, err := mod.run(actx, s, ActionCall{
		FlowID: r.FlowID, FlowName: r.FlowName, Description: description, RunID: r.ID,
		Config: resolveMap(st.Action.Config, scope), Detail: r.Context.Detail, Chain: r.Context.Chain,
	})
	result := "success"
	if err != nil {
		result = "error"
		s.log.Warn("automation: action en échec", "flow", r.FlowName, "step", st.ID, "action", st.Action.Type, "err", err)
	}
	adminmetrics.Automation.ActionsTotal.WithLabelValues(st.Action.Type, result).Inc()
	return out, err
}

func (s *Service) suspendApproval(r *Run, st *Step, scope map[string]any, started time.Time) {
	cfg := resolveMap(st.Config, scope)
	msg := cfgStr(cfg, "message")
	r.Status, r.Cursor, r.ResumeAt = RunWaitingApproval, st.ID, nil
	if raw := cfgStr(cfg, "timeout"); raw != "" {
		if d, err := time.ParseDuration(raw); err == nil && d > 0 {
			at := s.now().Add(d)
			r.ResumeAt = &at
		}
	}
	s.logStep(r.ID, StepLog{StepID: st.ID, Type: st.Type, Status: "waiting", Detail: msg, StartedAt: started})
	s.saveRun(r)
	s.setLastStatus(r.FlowID, r.ID, r.Status)
	text := "Approbation requise"
	if msg != "" {
		text += " : " + msg
	}
	s.emitNotify(r.FlowID, r.FlowName, "warning", text, map[string]any{"run_id": r.ID, "approval": true}, r.Context.Chain)
}

// runCall lance un playbook. Sans attente, l'exécution continue ; avec attente, elle se suspend jusqu'à la
// fin de l'appelé (resumeParent). Retourne false si l'exécution s'arrête ou se suspend.
func (s *Service) runCall(ctx context.Context, r *Run, st *Step, scope map[string]any, started time.Time, ix stepIndex) bool {
	cfg := resolveMap(st.Config, scope)
	target, err := s.getFlow(ctx, cfgStr(cfg, "flow_id"))
	switch {
	case err != nil:
		err = fmt.Errorf("playbook appelé introuvable")
	case target.Trigger.Kind != TriggerManual:
		err = fmt.Errorf("%s n'est pas un playbook (déclenchement manuel)", target.Name)
	case !target.Enabled:
		err = fmt.Errorf("le playbook %s est désactivé", target.Name)
	case r.Depth+1 > maxDepth || contains(r.Context.Chain, target.ID) || target.ID == r.FlowID:
		err = fmt.Errorf("appel circulaire ou trop profond vers %s", target.Name)
	}
	if err != nil {
		return s.stepDone(r, st, started, nil, err, ix)
	}
	inputs, _ := cfg["inputs"].(map[string]any)
	detail, err := applyInputs(target, inputs)
	if err != nil {
		return s.stepDone(r, st, started, nil, err, ix)
	}
	wait := true
	if w, ok := cfg["wait"].(bool); ok {
		wait = w
	}
	o := fireOpts{source: "call:" + r.ID, detail: detail, chain: append(append([]string{}, r.Context.Chain...), r.FlowID), manual: true, depth: r.Depth + 1}
	if wait {
		o.parentRunID, o.parentStepID = r.ID, st.ID
		// La suspension est enregistrée avant le lancement : un appelé très court peut finir avant
		// que l'appelant ne se mette en attente, et ne trouverait alors personne à reprendre.
		r.Status, r.Cursor = RunWaitingChild, st.ID
		s.saveRun(r)
		s.logStep(r.ID, StepLog{StepID: st.ID, Type: st.Type, Status: "waiting", Detail: "attend la fin de " + target.Name, StartedAt: started})
	}
	child, err := s.startRun(ctx, target, o)
	if err != nil {
		if wait {
			s.claimRun(r.ID, RunWaitingChild)
			r.Status = RunRunning
		}
		return s.stepDone(r, st, started, nil, err, ix)
	}
	if wait {
		return false
	}
	return s.stepDone(r, st, started, map[string]any{"run_id": child.ID, "status": "started"}, nil, ix)
}

// applyInputs vérifie et complète les paramètres d'un playbook (valeurs par défaut de ses entrées).
func applyInputs(f *Flow, in map[string]any) (map[string]any, error) {
	out := map[string]any{}
	for k, v := range in {
		out[k] = v
	}
	if f.Trigger.Manual == nil {
		return out, nil
	}
	for _, field := range f.Trigger.Manual.Inputs {
		if v, ok := out[field.Key]; (!ok || v == nil || v == "") && field.Default != nil {
			out[field.Key] = field.Default
		}
		if v, ok := out[field.Key]; field.Required && (!ok || v == nil || v == "") {
			return nil, invalid("paramètre %q requis", field.Key)
		}
	}
	return out, nil
}

// finish termine une exécution et reprend l'appelant qui l'attend.
func (s *Service) finish(r *Run, status RunStatus, errMsg string) {
	now := s.now()
	r.Status, r.Error, r.Cursor, r.ResumeAt, r.FinishedAt = status, errMsg, "", nil, &now
	s.saveRun(r)
	s.setLastStatus(r.FlowID, r.ID, status)
	adminmetrics.Automation.RunsTotal.WithLabelValues(string(r.TriggerKind), string(status)).Inc()
	if r.ParentRunID != "" {
		s.resumeParent(r)
	}
}

func (s *Service) resumeParent(child *Run) {
	parent, err := s.loadRun(context.Background(), child.ParentRunID)
	if err != nil || parent.Status != RunWaitingChild || parent.Cursor != child.ParentStepID {
		return
	}
	if !s.claimRun(parent.ID, RunWaitingChild) {
		return
	}
	parent.Status = RunRunning
	ix := indexSteps(parent.definition.Steps)
	pos, ok := ix[parent.Cursor]
	if !ok {
		s.finish(parent, RunFailed, "étape d'appel introuvable")
		return
	}
	out := map[string]any{"run_id": child.ID, "status": string(child.Status), "steps": stepsAny(child.Context.Steps)}
	var callErr error
	if child.Status != RunCompleted {
		callErr = fmt.Errorf("le playbook appelé s'est terminé en %s", child.Status)
	}
	if s.stepDone(parent, pos.step, child.StartedAt, out, callErr, ix) {
		s.advance(parent)
	}
}

func stepsAny(m map[string]map[string]any) map[string]any {
	out := make(map[string]any, len(m))
	for k, v := range m {
		out[k] = v
	}
	return out
}

func (s *Service) cancelled(runID string) bool {
	var status string
	_ = s.db.QueryRow(`SELECT status FROM flow_runs WHERE id=?`, runID).Scan(&status)
	return status == string(RunCancelled)
}

// resumeDue reprend les attentes échues et applique l'échéance des approbations.
func (s *Service) resumeDue() {
	rows, err := s.db.Query(`SELECT id, status FROM flow_runs WHERE status IN (?,?) AND resume_at IS NOT NULL AND resume_at <= ?`,
		string(RunWaiting), string(RunWaitingApproval), sqltime.Format(s.now()))
	if err != nil {
		return
	}
	type due struct{ id, status string }
	var list []due
	for rows.Next() {
		var d due
		if rows.Scan(&d.id, &d.status) == nil {
			list = append(list, d)
		}
	}
	rows.Close()
	for _, d := range list {
		if d.status == string(RunWaitingApproval) {
			s.approvalTimeout(d.id)
			continue
		}
		if !s.claimRun(d.id, RunWaiting) {
			continue
		}
		r, err := s.loadRun(context.Background(), d.id)
		if err != nil {
			continue
		}
		s.inflight.Add(1)
		go func() {
			defer s.inflight.Done()
			s.advance(r)
		}()
	}
}

func (s *Service) approvalTimeout(runID string) {
	r, err := s.loadRun(context.Background(), runID)
	if err != nil {
		return
	}
	pos, ok := indexSteps(r.definition.Steps)[r.Cursor]
	if !ok {
		return
	}
	approve := cfgStr(resolveMap(pos.step.Config, runScope(r)), "on_timeout") == "approve"
	_ = s.decide(r, approve, "délai expiré")
}

// Decide approuve ou refuse l'exécution suspendue sur une étape d'approbation.
func (s *Service) Decide(ctx context.Context, runID string, approve bool, actor string) error {
	r, err := s.loadRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.Status != RunWaitingApproval {
		return invalid("cette exécution n'attend pas d'approbation (%s)", r.Status)
	}
	return s.decide(r, approve, actor)
}

func (s *Service) decide(r *Run, approve bool, actor string) error {
	if !s.claimRun(r.ID, RunWaitingApproval) {
		return invalid("décision déjà prise")
	}
	r.Status = RunRunning
	ix := indexSteps(r.definition.Steps)
	stepID := r.Cursor
	decision, status := "rejected", "rejected"
	if approve {
		decision, status = "approved", "approved"
	}
	r.Context.Steps[stepID] = map[string]any{"decision": decision, "actor": actor}
	s.logStep(r.ID, StepLog{StepID: stepID, Type: StepApproval, Status: status, Actor: actor, StartedAt: s.now()})
	if !approve {
		s.finish(r, RunRejected, "refusée par "+actor)
		return nil
	}
	r.Cursor = ix.after(stepID)
	s.saveRun(r)
	s.inflight.Add(1)
	go func() {
		defer s.inflight.Done()
		s.advance(r)
	}()
	return nil
}

// Cancel annule une exécution en cours ou en attente, et les playbooks qu'elle attend.
func (s *Service) Cancel(ctx context.Context, runID, actor string) error {
	r, err := s.loadRun(ctx, runID)
	if err != nil {
		return err
	}
	if r.Status.Finished() {
		return invalid("exécution déjà terminée (%s)", r.Status)
	}
	now := sqltime.Format(s.now())
	msg := "annulée par " + actor
	_, err = s.db.ExecContext(ctx, `UPDATE flow_runs SET status=?, error=?, cursor='', resume_at=NULL, updated_at=?, finished_at=?
		WHERE (id=? OR parent_run_id=?) AND status IN (?,?,?,?)`, string(RunCancelled), msg, now, now, runID, runID,
		string(RunRunning), string(RunWaiting), string(RunWaitingApproval), string(RunWaitingChild))
	if err == nil {
		s.setLastStatus(r.FlowID, r.ID, RunCancelled)
	}
	return err
}

// recoverRuns traite les exécutions laissées par l'arrêt précédent. Une étape en cours pendant l'arrêt peut
// avoir agi ou non : l'exécution est marquée interrompue, jamais relancée d'office (une action rejouée
// pourrait agir deux fois) ; « Rejouer » la relance à la main. Les attentes et approbations reprennent
// d'elles-mêmes (resumeDue, Decide).
func (s *Service) recoverRuns() {
	now := sqltime.Format(s.now())
	rows, err := s.db.Query(`SELECT id FROM flow_runs WHERE status=?`, string(RunRunning))
	if err != nil {
		return
	}
	var ids []string
	for rows.Next() {
		var id string
		if rows.Scan(&id) == nil {
			ids = append(ids, id)
		}
	}
	rows.Close()
	for _, id := range ids {
		_, _ = s.db.Exec(`UPDATE flow_runs SET status=?, error=?, updated_at=?, finished_at=? WHERE id=? AND status=?`,
			string(RunInterrupted), "l'Admin s'est arrêté pendant l'exécution", now, now, id, string(RunRunning))
		if r, err := s.loadRun(context.Background(), id); err == nil {
			s.setLastStatus(r.FlowID, r.ID, RunInterrupted)
			if r.ParentRunID != "" {
				s.resumeParent(r)
			}
		}
	}
}
