// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"path/filepath"
	"time"

	"github.com/google/uuid"
	"github.com/vincamok/goproxify/internal/admin/adminmetrics"
)

const defaultCooldown = 5 * time.Minute

type fireOpts struct {
	source string
	detail map[string]any
	chain  []string
	actor  string
	// manual : lancé par une personne ou par un autre flux. Les garde-fous (sourdine, délai, concurrence)
	// filtrent les déclenchements automatiques, pas une demande explicite.
	manual       bool
	parentRunID  string
	parentStepID string
	depth        int
}

// cooldownOf retourne le délai minimum d'un flux : défaut 5 min pour une condition ou un événement, qui
// restent vrais ou se répètent ; aucun pour un horaire.
func cooldownOf(f *Flow) time.Duration {
	if f.Guard.CooldownSec > 0 {
		return time.Duration(f.Guard.CooldownSec) * time.Second
	}
	if f.Trigger.Kind == TriggerCondition || f.Trigger.Kind == TriggerEvent {
		return defaultCooldown
	}
	return 0
}

// fire applique les garde-fous puis démarre une exécution.
func (s *Service) fire(ctx context.Context, f *Flow, o fireOpts) (*Run, error) {
	if !o.manual {
		if s.silenced(ctx, f.ID) {
			if s.noteOnce("sil:"+f.ID, f) {
				s.recordFailure(f, "", RunSilenced, o.detail)
			}
			return nil, nil
		}
		key := f.ID
		if f.Guard.CooldownKey != "" {
			key += "|" + text(resolve(f.Guard.CooldownKey, map[string]any{"detail": o.detail, "flow": flowScope(f)["flow"]}))
		}
		if cd := cooldownOf(f); cd > 0 {
			s.mu.Lock()
			last, seen := s.cooldowns[key]
			if !seen && key == f.ID && f.State != nil && f.State.LastFiredAt != nil {
				last = *f.State.LastFiredAt // après un redémarrage de l'Admin
			}
			if s.now().Sub(last) < cd {
				s.mu.Unlock()
				return nil, nil
			}
			s.cooldowns[key] = s.now()
			s.mu.Unlock()
		}
		max := f.Guard.MaxConcurrent
		if max <= 0 {
			max = 1
		}
		if s.activeRuns(ctx, f.ID) >= max {
			return nil, nil
		}
	}
	return s.startRun(ctx, f, o)
}

// noteOnce limite à un par délai minimum (au moins une minute) les exécutions journalisées sans rien faire
// (déclenchement en sourdine, condition en erreur), pour ne pas remplir le journal à chaque évaluation.
func (s *Service) noteOnce(key string, f *Flow) bool {
	every := cooldownOf(f)
	if every < time.Minute {
		every = time.Minute
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.now().Sub(s.noted[key]) < every {
		return false
	}
	s.noted[key] = s.now()
	return true
}

// recordFailure journalise un déclenchement sans exécution (sourdine, condition en erreur).
func (s *Service) recordFailure(f *Flow, errMsg string, status RunStatus, detail map[string]any) {
	now := s.now()
	r := &Run{ID: uuid.NewString(), FlowID: f.ID, FlowName: f.Name, FlowVersion: f.Version, Source: "admin",
		TriggerKind: f.Trigger.Kind, Status: status, Error: errMsg, StartedAt: now, FinishedAt: &now,
		Context: RunContext{Detail: detail, Steps: map[string]map[string]any{}}, definition: f.definition()}
	if err := s.insertRun(context.Background(), r); err != nil {
		s.log.Warn("automation: journal", "flow", f.Name, "err", err)
		return
	}
	s.recordFired(f.ID, r.ID, status, false)
	adminmetrics.Automation.RunsTotal.WithLabelValues(string(f.Trigger.Kind), string(status)).Inc()
}

func (s *Service) silenced(ctx context.Context, flowID string) bool {
	list, err := s.querySilences(ctx, true)
	if err != nil {
		return false
	}
	now := s.now()
	for _, sl := range list {
		if sl.Active(now, flowID) {
			return true
		}
	}
	return false
}

func (s *Service) activeRuns(ctx context.Context, flowID string) int {
	var n int
	_ = s.db.QueryRowContext(ctx, `SELECT COUNT(*) FROM flow_runs WHERE flow_id=? AND status IN (?,?,?,?)`,
		flowID, string(RunRunning), string(RunWaiting), string(RunWaitingApproval), string(RunWaitingChild)).Scan(&n)
	return n
}

func matchGlob(pattern, v string) (bool, error) {
	if pattern == "" {
		return true, nil
	}
	return filepath.Match(pattern, v)
}

func adminmetricsEval(d time.Duration) {
	adminmetrics.Automation.EvalsTotal.Inc()
	adminmetrics.Automation.EvalDuration.Observe(d.Seconds())
}

func adminmetricsDrop() { adminmetrics.Automation.EventsDrop.Inc() }

func countActive(s *Service) {
	rows, err := s.db.Query(`SELECT trigger_kind, COUNT(*) FROM flows WHERE enabled=1 GROUP BY trigger_kind`)
	if err != nil {
		return
	}
	defer rows.Close()
	counts := map[string]float64{}
	for rows.Next() {
		var k string
		var n float64
		if rows.Scan(&k, &n) == nil {
			counts[k] = n
		}
	}
	for _, k := range []TriggerKind{TriggerCondition, TriggerEvent, TriggerSchedule, TriggerManual} {
		adminmetrics.Automation.ActiveFlows.WithLabelValues(string(k)).Set(counts[string(k)])
	}
}
