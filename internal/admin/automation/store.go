// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/vincamok/goproxify/internal/sqltime"
)

// ErrNotFound : flux, version, exécution ou silence introuvable.
var ErrNotFound = errors.New("introuvable")

const maxVersions = 20

func copyJSON(src, dst any) {
	b, _ := json.Marshal(src)
	_ = json.Unmarshal(b, dst)
}

// dbTime lit une colonne DATETIME, que le pilote la rende en time.Time ou en texte.
type dbTime struct {
	T     time.Time
	Valid bool
}

func (d *dbTime) Scan(v any) error {
	switch t := v.(type) {
	case nil:
		d.Valid = false
	case time.Time:
		d.T, d.Valid = t, true
	case string:
		d.T, _ = sqltime.Parse(t)
		d.Valid = !d.T.IsZero()
	case []byte:
		d.T, _ = sqltime.Parse(string(t))
		d.Valid = !d.T.IsZero()
	default:
		return fmt.Errorf("date illisible : %T", v)
	}
	return nil
}

func (d dbTime) ptr() *time.Time {
	if !d.Valid {
		return nil
	}
	t := d.T
	return &t
}

func boolInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

const flowCols = `f.id, f.name, f.description, f.enabled, f.definition_json, f.origin_json, f.version, f.created_by,
	f.created_at, f.updated_at, COALESCE(st.fire_count,0), st.last_fired_at, COALESCE(st.last_run_id,''), COALESCE(st.last_run_status,'')`

func scanFlow(sc interface{ Scan(...any) error }) (*Flow, error) {
	var f Flow
	var enabled int
	var defJSON, originJSON string
	var created, updated, lastFired dbTime
	var state FlowState
	if err := sc.Scan(&f.ID, &f.Name, &f.Description, &enabled, &defJSON, &originJSON, &f.Version, &f.CreatedBy,
		&created, &updated, &state.FireCount, &lastFired, &state.LastRunID, &state.LastRunStatus); err != nil {
		return nil, err
	}
	f.Enabled = enabled == 1
	var def definition
	if err := json.Unmarshal([]byte(defJSON), &def); err != nil {
		return nil, fmt.Errorf("flux %s illisible : %w", f.ID, err)
	}
	f.Trigger, f.Guard, f.Steps = def.Trigger, def.Guard, def.Steps
	_ = json.Unmarshal([]byte(originJSON), &f.Origin)
	f.CreatedAt, f.UpdatedAt = created.T, updated.T
	state.LastFiredAt = lastFired.ptr()
	f.State = &state
	return &f, nil
}

func (s *Service) queryFlows(ctx context.Context, where string, args ...any) ([]*Flow, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT `+flowCols+` FROM flows f LEFT JOIN flow_state st ON st.flow_id=f.id `+where+` ORDER BY f.name COLLATE NOCASE`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Flow
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			s.log.Warn("automation: flux illisible ignoré", "err", err)
			continue
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (s *Service) getFlow(ctx context.Context, id string) (*Flow, error) {
	f, err := scanFlow(s.db.QueryRowContext(ctx, `SELECT `+flowCols+` FROM flows f LEFT JOIN flow_state st ON st.flow_id=f.id WHERE f.id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return f, err
}

// allFlows retourne tous les flux par identifiant (validation des appels).
func (s *Service) allFlows(ctx context.Context) (map[string]*Flow, error) {
	list, err := s.queryFlows(ctx, "")
	if err != nil {
		return nil, err
	}
	out := make(map[string]*Flow, len(list))
	for _, f := range list {
		out[f.ID] = f
	}
	return out, nil
}

func isUniqueErr(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE")
}

func (s *Service) insertFlow(ctx context.Context, f *Flow) error {
	defJSON, _ := json.Marshal(f.definition())
	originJSON, _ := json.Marshal(f.Origin)
	now := sqltime.Format(time.Now())
	_, err := s.db.ExecContext(ctx, `INSERT INTO flows (id, name, description, enabled, trigger_kind, definition_json, origin_json, version, created_by, created_at, updated_at)
		VALUES (?,?,?,?,?,?,?,?,?,?,?)`,
		f.ID, f.Name, f.Description, boolInt(f.Enabled), string(f.Trigger.Kind), string(defJSON), string(originJSON), f.Version, f.CreatedBy, now, now)
	if isUniqueErr(err) {
		return invalid("un flux nommé %q existe déjà", f.Name)
	}
	return err
}

func (s *Service) updateFlowRow(ctx context.Context, f *Flow) error {
	defJSON, _ := json.Marshal(f.definition())
	originJSON, _ := json.Marshal(f.Origin)
	res, err := s.db.ExecContext(ctx, `UPDATE flows SET name=?, description=?, enabled=?, trigger_kind=?, definition_json=?, origin_json=?, version=?, updated_at=? WHERE id=?`,
		f.Name, f.Description, boolInt(f.Enabled), string(f.Trigger.Kind), string(defJSON), string(originJSON), f.Version, sqltime.Format(time.Now()), f.ID)
	if isUniqueErr(err) {
		return invalid("un flux nommé %q existe déjà", f.Name)
	}
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

// snapshot enregistre la version courante de f et ne garde que les maxVersions dernières.
func (s *Service) snapshot(ctx context.Context, f *Flow, actor string) {
	defJSON, _ := json.Marshal(f.definition())
	originJSON, _ := json.Marshal(f.Origin)
	if _, err := s.db.ExecContext(ctx, `INSERT INTO flow_versions (flow_id, version, name, description, enabled, definition_json, origin_json, created_by, created_at)
		VALUES (?,?,?,?,?,?,?,?,?)`, f.ID, f.Version, f.Name, f.Description, boolInt(f.Enabled), string(defJSON), string(originJSON), actor, sqltime.Format(time.Now())); err != nil {
		s.log.Warn("automation: version non enregistrée", "flow", f.Name, "err", err)
		return
	}
	_, _ = s.db.ExecContext(ctx, `DELETE FROM flow_versions WHERE flow_id=? AND version <= ?`, f.ID, f.Version-maxVersions)
}

// Version est un instantané d'un flux.
type Version struct {
	Version   int       `json:"version"`
	Flow      *Flow     `json:"flow"`
	CreatedBy string    `json:"created_by,omitempty"`
	CreatedAt time.Time `json:"created_at"`
}

func (s *Service) queryVersions(ctx context.Context, flowID string, version int) ([]Version, error) {
	q := `SELECT version, name, description, enabled, definition_json, origin_json, created_by, created_at FROM flow_versions WHERE flow_id=?`
	args := []any{flowID}
	if version > 0 {
		q += ` AND version=?`
		args = append(args, version)
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY version DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Version
	for rows.Next() {
		var v Version
		var f Flow
		var enabled int
		var defJSON, originJSON string
		var created dbTime
		if rows.Scan(&v.Version, &f.Name, &f.Description, &enabled, &defJSON, &originJSON, &v.CreatedBy, &created) != nil {
			continue
		}
		var def definition
		_ = json.Unmarshal([]byte(defJSON), &def)
		_ = json.Unmarshal([]byte(originJSON), &f.Origin)
		f.ID, f.Enabled, f.Version = flowID, enabled == 1, v.Version
		f.Trigger, f.Guard, f.Steps = def.Trigger, def.Guard, def.Steps
		v.Flow, v.CreatedAt = &f, created.T
		out = append(out, v)
	}
	return out, rows.Err()
}

// ── Exécutions ──────────────────────────────────────────────────────────

func (s *Service) insertRun(ctx context.Context, r *Run) error {
	defJSON, _ := json.Marshal(r.definition)
	ctxJSON, _ := json.Marshal(r.Context)
	now := sqltime.Format(r.StartedAt)
	_, err := s.db.ExecContext(ctx, `INSERT INTO flow_runs (id, flow_id, flow_name, flow_version, definition_json, source, trigger_kind, status, cursor,
		context_json, parent_run_id, parent_step_id, depth, error, started_at, updated_at, finished_at) VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		r.ID, r.FlowID, r.FlowName, r.FlowVersion, string(defJSON), r.Source, string(r.TriggerKind), string(r.Status), r.Cursor,
		string(ctxJSON), r.ParentRunID, r.ParentStepID, r.Depth, r.Error, now, now, sqltime.Nullable(r.FinishedAt))
	return err
}

// saveRun enregistre l'avancement d'une exécution (statut, curseur, variables, reprise).
func (s *Service) saveRun(r *Run) {
	ctxJSON, _ := json.Marshal(r.Context)
	r.UpdatedAt = s.now()
	if _, err := s.db.Exec(`UPDATE flow_runs SET status=?, cursor=?, context_json=?, resume_at=?, error=?, updated_at=?, finished_at=? WHERE id=?`,
		string(r.Status), r.Cursor, string(ctxJSON), sqltime.Nullable(r.ResumeAt), r.Error, sqltime.Format(r.UpdatedAt), sqltime.Nullable(r.FinishedAt), r.ID); err != nil {
		s.log.Error("automation: enregistrement de l'exécution", "run", r.ID, "err", err)
	}
}

// claimRun passe une exécution d'un des états from à running, si personne ne l'a fait avant : une reprise,
// une décision et une échéance ne peuvent pas faire avancer la même exécution deux fois.
func (s *Service) claimRun(id string, from ...RunStatus) bool {
	ph := strings.TrimSuffix(strings.Repeat("?,", len(from)), ",")
	args := []any{string(RunRunning), sqltime.Format(s.now()), id}
	for _, st := range from {
		args = append(args, string(st))
	}
	res, err := s.db.Exec(`UPDATE flow_runs SET status=?, resume_at=NULL, updated_at=? WHERE id=? AND status IN (`+ph+`)`, args...)
	if err != nil {
		return false
	}
	n, _ := res.RowsAffected()
	return n == 1
}

const runCols = `id, flow_id, flow_name, flow_version, definition_json, source, trigger_kind, status, cursor, context_json, resume_at,
	parent_run_id, parent_step_id, depth, error, started_at, updated_at, finished_at`

func scanRun(sc interface{ Scan(...any) error }) (*Run, error) {
	var r Run
	var defJSON, ctxJSON, trig, status string
	var resume, started, updated, finished dbTime
	if err := sc.Scan(&r.ID, &r.FlowID, &r.FlowName, &r.FlowVersion, &defJSON, &r.Source, &trig, &status, &r.Cursor, &ctxJSON, &resume,
		&r.ParentRunID, &r.ParentStepID, &r.Depth, &r.Error, &started, &updated, &finished); err != nil {
		return nil, err
	}
	r.TriggerKind, r.Status = TriggerKind(trig), RunStatus(status)
	_ = json.Unmarshal([]byte(defJSON), &r.definition)
	_ = json.Unmarshal([]byte(ctxJSON), &r.Context)
	if r.Context.Detail == nil {
		r.Context.Detail = map[string]any{}
	}
	if r.Context.Steps == nil {
		r.Context.Steps = map[string]map[string]any{}
	}
	r.ResumeAt, r.FinishedAt = resume.ptr(), finished.ptr()
	r.StartedAt, r.UpdatedAt = started.T, updated.T
	return &r, nil
}

func (s *Service) loadRun(ctx context.Context, id string) (*Run, error) {
	r, err := scanRun(s.db.QueryRowContext(ctx, `SELECT `+runCols+` FROM flow_runs WHERE id=?`, id))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, ErrNotFound
	}
	return r, err
}

// RunFilter filtre la liste des exécutions.
type RunFilter struct {
	FlowID string
	Status []RunStatus
	Source string // préfixe : edge, manual, admin, call
	Since  time.Time
	Limit  int
}

func (s *Service) queryRuns(ctx context.Context, f RunFilter) ([]*Run, error) {
	var where []string
	var args []any
	if f.FlowID != "" {
		where, args = append(where, "flow_id=?"), append(args, f.FlowID)
	}
	if len(f.Status) > 0 {
		ph := strings.TrimSuffix(strings.Repeat("?,", len(f.Status)), ",")
		where = append(where, "status IN ("+ph+")")
		for _, st := range f.Status {
			args = append(args, string(st))
		}
	}
	if f.Source != "" {
		where, args = append(where, "source LIKE ?"), append(args, f.Source+"%")
	}
	if !f.Since.IsZero() {
		where, args = append(where, "started_at >= ?"), append(args, sqltime.Format(f.Since))
	}
	q := `SELECT ` + runCols + ` FROM flow_runs`
	if len(where) > 0 {
		q += ` WHERE ` + strings.Join(where, " AND ")
	}
	limit := f.Limit
	if limit <= 0 || limit > 500 {
		limit = 100
	}
	rows, err := s.db.QueryContext(ctx, q+fmt.Sprintf(` ORDER BY started_at DESC, rowid DESC LIMIT %d`, limit), args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []*Run
	for rows.Next() {
		if r, err := scanRun(rows); err == nil {
			out = append(out, r)
		}
	}
	return out, rows.Err()
}

func (s *Service) appendStep(runID string, l StepLog) {
	out := ""
	if len(l.Output) > 0 {
		b, _ := json.Marshal(l.Output)
		out = string(b)
	}
	if l.StartedAt.IsZero() {
		l.StartedAt = s.now()
	}
	if _, err := s.db.Exec(`INSERT INTO flow_run_steps (run_id, step_id, step_type, status, detail, output_json, actor, flow, started_at, finished_at)
		VALUES (?,?,?,?,?,?,?,?,?,?)`, runID, l.StepID, l.Type, l.Status, l.Detail, out, l.Actor, l.Flow,
		sqltime.Format(l.StartedAt), sqltime.Nullable(l.FinishedAt)); err != nil {
		s.log.Warn("automation: journal d'étape", "run", runID, "err", err)
	}
}

func (s *Service) stepLogs(ctx context.Context, runID string) []StepLog {
	rows, err := s.db.QueryContext(ctx, `SELECT step_id, step_type, status, detail, output_json, actor, flow, started_at, finished_at
		FROM flow_run_steps WHERE run_id=? ORDER BY id`, runID)
	if err != nil {
		return nil
	}
	defer rows.Close()
	var out []StepLog
	for rows.Next() {
		var l StepLog
		var outJSON string
		var started, finished dbTime
		if rows.Scan(&l.StepID, &l.Type, &l.Status, &l.Detail, &outJSON, &l.Actor, &l.Flow, &started, &finished) != nil {
			continue
		}
		if outJSON != "" {
			_ = json.Unmarshal([]byte(outJSON), &l.Output)
		}
		l.StartedAt, l.FinishedAt = started.T, finished.ptr()
		out = append(out, l)
	}
	return out
}

// recordFired met à jour l'état du flux après un déclenchement.
func (s *Service) recordFired(flowID, runID string, status RunStatus, fired bool) {
	now := sqltime.Format(s.now())
	var err error
	if fired {
		_, err = s.db.Exec(`INSERT INTO flow_state (flow_id, fire_count, last_fired_at, last_run_id, last_run_status) VALUES (?,1,?,?,?)
			ON CONFLICT(flow_id) DO UPDATE SET fire_count=fire_count+1, last_fired_at=excluded.last_fired_at,
			last_run_id=excluded.last_run_id, last_run_status=excluded.last_run_status`, flowID, now, runID, string(status))
	} else {
		_, err = s.db.Exec(`INSERT INTO flow_state (flow_id, last_run_id, last_run_status) VALUES (?,?,?)
			ON CONFLICT(flow_id) DO UPDATE SET last_run_id=excluded.last_run_id, last_run_status=excluded.last_run_status`, flowID, runID, string(status))
	}
	if err != nil {
		s.log.Warn("automation: état du flux", "flow", flowID, "err", err)
	}
}

func (s *Service) setLastStatus(flowID, runID string, status RunStatus) {
	_, _ = s.db.Exec(`UPDATE flow_state SET last_run_status=? WHERE flow_id=? AND last_run_id=?`, string(status), flowID, runID)
}

// purge supprime les exécutions terminées depuis plus de 30 jours.
func (s *Service) purge() {
	limit := sqltime.Format(s.now().AddDate(0, 0, -30))
	_, _ = s.db.Exec(`DELETE FROM flow_run_steps WHERE run_id IN (SELECT id FROM flow_runs WHERE finished_at IS NOT NULL AND finished_at < ?)`, limit)
	_, _ = s.db.Exec(`DELETE FROM flow_runs WHERE finished_at IS NOT NULL AND finished_at < ?`, limit)
}

// ── Silences ────────────────────────────────────────────────────────────

func (s *Service) querySilences(ctx context.Context, activeOnly bool) ([]Silence, error) {
	q := `SELECT id, name, rule_ids, starts_at, ends_at, created_at FROM automation_silences`
	var args []any
	if activeOnly {
		q += ` WHERE ends_at >= ?`
		args = append(args, sqltime.Format(s.now().Add(-time.Minute)))
	}
	rows, err := s.db.QueryContext(ctx, q+` ORDER BY starts_at DESC`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Silence{}
	for rows.Next() {
		var sl Silence
		var ids string
		var starts, ends, created dbTime
		if rows.Scan(&sl.ID, &sl.Name, &ids, &starts, &ends, &created) != nil {
			continue
		}
		_ = json.Unmarshal([]byte(ids), &sl.RuleIDs)
		if sl.RuleIDs == nil {
			sl.RuleIDs = []string{}
		}
		sl.StartsAt, sl.EndsAt, sl.CreatedAt = starts.T, ends.T, created.T
		out = append(out, sl)
	}
	return out, rows.Err()
}
