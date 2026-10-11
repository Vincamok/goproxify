// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// ErrTemplateManaged : la définition d'un flux issu d'un modèle se modifie par ses paramètres, ou après
// l'avoir détaché du modèle.
var ErrTemplateManaged = errors.New("flux géré par un modèle : modifiez ses paramètres, ou détachez-le pour l'éditer")

// decorate complète un flux pour la lecture : secrets masqués, placement, prochaine exécution, attentes.
func (s *Service) decorate(ctx context.Context, f *Flow) *Flow {
	out := maskFlow(f)
	out.Placement, out.PlacementReason = placement(f)
	if out.State == nil {
		out.State = &FlowState{}
	}
	if f.Trigger.Kind == TriggerSchedule && f.Trigger.Schedule != nil && f.Enabled {
		if expr, err := ParseExpr(f.Trigger.Schedule.Cron); err == nil {
			if next := expr.Next(s.now()); !next.IsZero() {
				out.State.NextRunAt = &next
			}
		}
	}
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_runs WHERE flow_id=? AND status IN (?,?,?)`,
		f.ID, string(RunWaiting), string(RunWaitingApproval), string(RunWaitingChild)).Scan(&out.State.Waiting)
	return out
}

// List retourne les flux, filtrés par type de déclencheur (vide = tous).
func (s *Service) List(ctx context.Context, kinds ...TriggerKind) ([]*Flow, error) {
	where, args := "", []any{}
	if len(kinds) > 0 {
		where = "WHERE f.trigger_kind IN (" + strings.TrimSuffix(strings.Repeat("?,", len(kinds)), ",") + ")"
		for _, k := range kinds {
			args = append(args, string(k))
		}
	}
	flows, err := s.queryFlows(ctx, where, args...)
	if err != nil {
		return nil, err
	}
	out := make([]*Flow, 0, len(flows))
	for _, f := range flows {
		out = append(out, s.decorate(ctx, f))
	}
	return out, nil
}

// Get retourne un flux (secrets masqués).
func (s *Service) Get(ctx context.Context, id string) (*Flow, error) {
	f, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	return s.decorate(ctx, f), nil
}

// check normalise et valide f contre les flux enregistrés.
func (s *Service) check(ctx context.Context, f *Flow) error {
	normalize(f)
	all, err := s.allFlows(ctx)
	if err != nil {
		return err
	}
	all[f.ID] = f
	return validate(f, all)
}

// Create enregistre un nouveau flux.
func (s *Service) Create(ctx context.Context, f *Flow, actor string) (*Flow, error) {
	f.ID = uuid.NewString()
	f.Version, f.CreatedBy, f.State = 1, actor, nil
	if f.Origin.Kind == OriginTemplate {
		return nil, invalid("un flux issu d'un modèle s'installe depuis le modèle")
	}
	f.Origin = Origin{Kind: OriginManual}
	if err := s.check(ctx, f); err != nil {
		return nil, err
	}
	if err := s.insertFlow(ctx, f); err != nil {
		return nil, err
	}
	s.snapshot(ctx, f, actor)
	s.changed(f, nil)
	return s.Get(ctx, f.ID)
}

// Update remplace la définition d'un flux construit dans l'éditeur. Les secrets renvoyés masqués ou omis
// sont conservés.
func (s *Service) Update(ctx context.Context, id string, next *Flow, actor string) (*Flow, error) {
	old, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	if old.Origin.Kind == OriginTemplate {
		return nil, ErrTemplateManaged
	}
	next.ID, next.Origin, next.CreatedBy, next.CreatedAt = id, old.Origin, old.CreatedBy, old.CreatedAt
	next.Version = old.Version + 1
	keepSecrets(old, next)
	if err := s.check(ctx, next); err != nil {
		return nil, err
	}
	if err := s.updateFlowRow(ctx, next); err != nil {
		return nil, err
	}
	s.snapshot(ctx, next, actor)
	s.changed(next, old)
	return s.Get(ctx, id)
}

// SetEnabled active ou désactive un flux (sans nouvelle version).
func (s *Service) SetEnabled(ctx context.Context, id string, enabled bool) (*Flow, error) {
	f, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	if _, err := s.db.ExecContext(ctx, `UPDATE flows SET enabled=?, updated_at=? WHERE id=?`, boolInt(enabled), sqltime.Format(s.now()), id); err != nil {
		return nil, err
	}
	f.Enabled = enabled
	s.changed(f, f)
	return s.Get(ctx, id)
}

// Delete supprime un flux, ses versions et son état. Un flux appelé par un autre ne peut pas être supprimé.
func (s *Service) Delete(ctx context.Context, id string) error {
	f, err := s.getFlow(ctx, id)
	if err != nil {
		return err
	}
	all, err := s.allFlows(ctx)
	if err != nil {
		return err
	}
	for _, other := range all {
		used := false
		walkSteps(other.Steps, func(st *Step) { used = used || (st.Type == StepCall && cfgStr(st.Config, "flow_id") == id) })
		if used && other.ID != id {
			return invalid("%s est appelé par le flux %s", f.Name, other.Name)
		}
	}
	for _, q := range []string{`DELETE FROM flows WHERE id=?`, `DELETE FROM flow_state WHERE flow_id=?`, `DELETE FROM flow_versions WHERE flow_id=?`} {
		if _, err := s.db.ExecContext(ctx, q, id); err != nil {
			return err
		}
	}
	s.changed(nil, f)
	return nil
}

// changed signale aux passerelles un changement qui concerne un flux exécuté par elles.
func (s *Service) changed(next, old *Flow) {
	for _, f := range []*Flow{next, old} {
		if f != nil && f.Trigger.Kind == TriggerCondition {
			if p, _ := placement(f); p == PlacementEdge {
				s.edgeChanged()
				return
			}
		}
	}
}

// Versions retourne l'historique d'un flux (secrets masqués).
func (s *Service) Versions(ctx context.Context, id string) ([]Version, error) {
	if _, err := s.getFlow(ctx, id); err != nil {
		return nil, err
	}
	list, err := s.queryVersions(ctx, id, 0)
	for i := range list {
		list[i].Flow = maskFlow(list[i].Flow)
	}
	if list == nil {
		list = []Version{}
	}
	return list, err
}

// Restore rétablit une version : elle devient la version courante (une nouvelle version est créée).
func (s *Service) Restore(ctx context.Context, id string, version int, actor string) (*Flow, error) {
	old, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	list, err := s.queryVersions(ctx, id, version)
	if err != nil {
		return nil, err
	}
	if len(list) == 0 {
		return nil, ErrNotFound
	}
	next := list[0].Flow
	next.ID, next.CreatedBy, next.CreatedAt, next.Version = id, old.CreatedBy, old.CreatedAt, old.Version+1
	if err := s.check(ctx, next); err != nil {
		return nil, err
	}
	if err := s.updateFlowRow(ctx, next); err != nil {
		return nil, err
	}
	s.snapshot(ctx, next, actor)
	s.changed(next, old)
	return s.Get(ctx, id)
}

// Detach détache un flux de son modèle : il devient un flux de l'éditeur, sa définition est conservée.
func (s *Service) Detach(ctx context.Context, id, actor string) (*Flow, error) {
	f, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	if f.Origin.Kind != OriginTemplate {
		return s.Get(ctx, id)
	}
	f.Origin, f.Version = Origin{Kind: OriginManual}, f.Version+1
	if err := s.updateFlowRow(ctx, f); err != nil {
		return nil, err
	}
	s.snapshot(ctx, f, actor)
	return s.Get(ctx, id)
}

// TemplateUpdate : ce qu'on modifie d'un flux issu d'un modèle.
type TemplateUpdate struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Enabled     bool           `json:"enabled"`
	Params      map[string]any `json:"params"`
}

// UpdateParams rend de nouveau un flux issu d'un modèle avec de nouveaux paramètres (version courante du
// modèle). Les identifiants d'étape du modèle sont stables : les secrets saisis restent attachés.
func (s *Service) UpdateParams(ctx context.Context, id string, u TemplateUpdate, actor string) (*Flow, error) {
	old, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	if old.Origin.Kind != OriginTemplate {
		return nil, invalid("ce flux n'est pas issu d'un modèle")
	}
	tpl, ok := templateByID(old.Origin.TemplateID)
	if !ok {
		return nil, invalid("le modèle %q n'existe plus : détachez le flux pour le modifier", old.Origin.TemplateID)
	}
	if man, ok := templateParamsManifest(old.Origin); ok {
		u.Params = man.KeepSecrets(old.Origin.Params, normalizeJSON(u.Params))
	}
	next, _, err := tpl.render(u.Params)
	if err != nil {
		return nil, err
	}
	next.ID, next.CreatedBy, next.CreatedAt, next.Version = id, old.CreatedBy, old.CreatedAt, old.Version+1
	next.Name, next.Description, next.Enabled = strings.TrimSpace(u.Name), u.Description, u.Enabled
	if next.Name == "" {
		next.Name = old.Name
	}
	keepSecrets(old, next)
	if err := s.check(ctx, next); err != nil {
		return nil, err
	}
	if err := s.updateFlowRow(ctx, next); err != nil {
		return nil, err
	}
	s.snapshot(ctx, next, actor)
	s.changed(next, old)
	return s.Get(ctx, id)
}

// Install crée un flux depuis un modèle.
func (s *Service) Install(ctx context.Context, templateID string, u TemplateUpdate, actor string) (*Flow, error) {
	tpl, ok := templateByID(templateID)
	if !ok {
		return nil, ErrNotFound
	}
	f, _, err := tpl.render(u.Params)
	if err != nil {
		return nil, err
	}
	if name := strings.TrimSpace(u.Name); name != "" {
		f.Name = name
	}
	if u.Description != "" {
		f.Description = u.Description
	}
	f.Enabled = u.Enabled
	f.ID, f.Version, f.CreatedBy = uuid.NewString(), 1, actor
	if err := s.check(ctx, f); err != nil {
		return nil, err
	}
	if err := s.insertFlow(ctx, f); err != nil {
		return nil, err
	}
	s.snapshot(ctx, f, actor)
	s.changed(f, nil)
	return s.Get(ctx, f.ID)
}

// Preview rend un modèle avec des paramètres, sans l'enregistrer.
func (s *Service) Preview(ctx context.Context, templateID string, params map[string]any) (*Flow, error) {
	tpl, ok := templateByID(templateID)
	if !ok {
		return nil, ErrNotFound
	}
	f, _, err := tpl.render(params)
	if err != nil {
		return nil, err
	}
	f.ID = "preview"
	if err := s.check(ctx, f); err != nil {
		return nil, err
	}
	out := maskFlow(f)
	out.Placement, out.PlacementReason = placement(f)
	return out, nil
}

// TemplateInfo est un modèle tel que listé, avec le nombre de flux qui en sont issus.
type TemplateInfo struct {
	Template
	Installed int `json:"installed"`
}

// ListTemplates retourne les modèles.
func (s *Service) ListTemplates(ctx context.Context) ([]TemplateInfo, error) {
	list, err := Templates()
	if err != nil {
		return nil, err
	}
	counts := map[string]int{}
	rows, err := s.db.QueryContext(ctx, `SELECT json_extract(origin_json,'$.template_id'), COUNT(*) FROM flows
		WHERE json_extract(origin_json,'$.kind')='template' GROUP BY 1`)
	if err == nil {
		for rows.Next() {
			var id string
			var n int
			if rows.Scan(&id, &n) == nil {
				counts[id] = n
			}
		}
		rows.Close()
	}
	out := make([]TemplateInfo, 0, len(list))
	for _, t := range list {
		out = append(out, TemplateInfo{Template: t, Installed: counts[t.ID]})
	}
	return out, nil
}

// RunResult est la réponse d'un lancement manuel.
type RunResult struct {
	RunID   string         `json:"run_id,omitempty"`
	Matched bool           `json:"matched"`
	Detail  map[string]any `json:"detail,omitempty"`
}

// RunNow lance un flux à la main. Un flux à condition l'évalue d'abord et ne s'exécute que si elle est vraie ;
// les autres s'exécutent avec les paramètres donnés. Les garde-fous ne s'appliquent pas.
func (s *Service) RunNow(ctx context.Context, id string, inputs map[string]any, actor string) (*RunResult, error) {
	f, err := s.getFlow(ctx, id)
	if err != nil {
		return nil, err
	}
	detail := normalizeJSON(inputs)
	if f.Trigger.Kind == TriggerCondition {
		matched, d, err := s.evalCond(ctx, f.Trigger.Condition, flowScope(f))
		if err != nil {
			return nil, invalid("condition : %v", err)
		}
		if !matched {
			return &RunResult{Matched: false}, nil
		}
		detail = d
	} else if f.Trigger.Kind == TriggerManual {
		if detail, err = applyInputs(f, detail); err != nil {
			return nil, err
		}
	}
	run, err := s.fire(ctx, f, fireOpts{source: "manual:" + actor, detail: detail, actor: actor, manual: true})
	if err != nil {
		return nil, err
	}
	return &RunResult{RunID: run.ID, Matched: true, Detail: detail}, nil
}

// Runs liste les exécutions.
func (s *Service) Runs(ctx context.Context, f RunFilter) ([]*Run, error) {
	list, err := s.queryRuns(ctx, f)
	if err != nil {
		return nil, err
	}
	for _, r := range list {
		s.describePending(r)
	}
	if list == nil {
		list = []*Run{}
	}
	return list, nil
}

// GetRun retourne une exécution et le journal de ses étapes.
func (s *Service) GetRun(ctx context.Context, id string) (*Run, error) {
	r, err := s.loadRun(ctx, id)
	if err != nil {
		return nil, err
	}
	r.Steps = s.stepLogs(ctx, id)
	s.describePending(r)
	return r, nil
}

func (s *Service) describePending(r *Run) {
	if r.Status != RunWaitingApproval {
		return
	}
	if pos, ok := indexSteps(r.definition.Steps)[r.Cursor]; ok {
		r.Pending = &PendingApproval{StepID: r.Cursor, Message: cfgStr(resolveMap(pos.step.Config, runScope(r)), "message")}
	}
}

// Replay relance un flux avec le contexte d'une exécution passée (sans réévaluer son déclencheur), par
// exemple après une interruption ou un échec.
func (s *Service) Replay(ctx context.Context, runID, actor string) (*RunResult, error) {
	r, err := s.loadRun(ctx, runID)
	if err != nil {
		return nil, err
	}
	if !r.Status.Finished() {
		return nil, invalid("exécution encore en cours")
	}
	f, err := s.getFlow(ctx, r.FlowID)
	if err != nil {
		return nil, invalid("le flux d'origine n'existe plus")
	}
	run, err := s.fire(ctx, f, fireOpts{source: "manual:" + actor, detail: r.Context.Detail, actor: actor, manual: true, chain: r.Context.Chain})
	if err != nil {
		return nil, err
	}
	return &RunResult{RunID: run.ID, Matched: true, Detail: r.Context.Detail}, nil
}

// Silences retourne les mises en sourdine.
func (s *Service) Silences(ctx context.Context) ([]Silence, error) {
	return s.querySilences(ctx, false)
}

// CreateSilence enregistre une mise en sourdine.
func (s *Service) CreateSilence(ctx context.Context, sl Silence) (*Silence, error) {
	sl.Name = strings.TrimSpace(sl.Name)
	if sl.Name == "" {
		return nil, invalid("nom requis")
	}
	if sl.StartsAt.IsZero() {
		sl.StartsAt = s.now()
	}
	if !sl.EndsAt.After(sl.StartsAt) {
		return nil, invalid("la fin doit suivre le début")
	}
	if sl.RuleIDs == nil {
		sl.RuleIDs = []string{}
	}
	ids, _ := jsonString(sl.RuleIDs)
	sl.ID = uuid.NewString()
	sl.CreatedAt = s.now()
	if _, err := s.db.ExecContext(ctx, `INSERT INTO automation_silences (id, name, rule_ids, starts_at, ends_at, created_at) VALUES (?,?,?,?,?,?)`,
		sl.ID, sl.Name, ids, sqltime.Format(sl.StartsAt), sqltime.Format(sl.EndsAt), sqltime.Format(sl.CreatedAt)); err != nil {
		return nil, err
	}
	return &sl, nil
}

// DeleteSilence supprime une mise en sourdine.
func (s *Service) DeleteSilence(ctx context.Context, id string) error {
	res, err := s.db.ExecContext(ctx, `DELETE FROM automation_silences WHERE id=?`, id)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// Stats résume l'activité pour la vue d'ensemble.
type Stats struct {
	Flows     map[TriggerKind]int `json:"flows"`
	Enabled   int                 `json:"enabled"`
	Runs24h   int                 `json:"runs_24h"`
	Failed24h int                 `json:"failed_24h"`
	Waiting   int                 `json:"waiting_approval"`
	Hourly    []int               `json:"hourly"` // exécutions par heure sur 24 h, la plus ancienne d'abord
	Templates int                 `json:"templates"`
}

// Stats calcule les statistiques de la vue d'ensemble.
func (s *Service) Stats(ctx context.Context) (*Stats, error) {
	st := &Stats{Flows: map[TriggerKind]int{}, Hourly: make([]int, 24)}
	rows, err := s.db.QueryContext(ctx, `SELECT trigger_kind, enabled, COUNT(*) FROM flows GROUP BY 1, 2`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var k string
		var en, n int
		if rows.Scan(&k, &en, &n) == nil {
			st.Flows[TriggerKind(k)] += n
			if en == 1 {
				st.Enabled += n
			}
		}
	}
	rows.Close()
	now := s.now()
	from := now.Add(-24 * time.Hour)
	rows, err = s.db.QueryContext(ctx, `SELECT status, started_at FROM flow_runs WHERE started_at >= ?`, sqltime.Format(from))
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var status string
		var at dbTime
		if rows.Scan(&status, &at) != nil {
			continue
		}
		st.Runs24h++
		if status == string(RunFailed) || status == string(RunInterrupted) {
			st.Failed24h++
		}
		if h := int(at.T.Sub(from) / time.Hour); h >= 0 && h < 24 {
			st.Hourly[h]++
		}
	}
	rows.Close()
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_runs WHERE status=?`, string(RunWaitingApproval)).Scan(&st.Waiting)
	if list, err := Templates(); err == nil {
		st.Templates = len(list)
	}
	return st, nil
}

func jsonString(v any) (string, error) {
	b, err := json.Marshal(v)
	return string(b), err
}
