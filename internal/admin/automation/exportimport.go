// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package automation

import (
	"context"
	"encoding/json"
	"fmt"
	"sort"
	"time"

	"github.com/google/uuid"
	"gopkg.in/yaml.v3"

	"github.com/vincamok/goproxify/internal/admin/alerting/channels"
	"github.com/vincamok/goproxify/internal/sqltime"
)

// Format d'export (GitOps) : flux, canaux de notification et mises en sourdine. Les secrets sont masqués ;
// à l'import, un flux ou un canal existant (même nom) garde les siens. Les flux gardent leur identifiant
// pour que les étapes « lancer un playbook » d'un même document se retrouvent.
const exportVersion = 2

type exportedChannel struct {
	Name    string         `yaml:"name"`
	Type    string         `yaml:"type"`
	Config  map[string]any `yaml:"config"`
	Enabled bool           `yaml:"enabled"`
}

type exportedSilence struct {
	Name     string   `yaml:"name"`
	RuleIDs  []string `yaml:"rule_ids,omitempty"`
	StartsAt string   `yaml:"starts_at"`
	EndsAt   string   `yaml:"ends_at"`
}

type exportDoc struct {
	Version  int               `yaml:"version"`
	Flows    []map[string]any  `yaml:"flows,omitempty"`
	Channels []exportedChannel `yaml:"channels,omitempty"`
	Silences []exportedSilence `yaml:"silences,omitempty"`
}

// Export retourne la configuration d'automatisation en YAML.
func (s *Service) Export(ctx context.Context) ([]byte, error) {
	doc := exportDoc{Version: exportVersion}
	flows, err := s.queryFlows(ctx, "")
	if err != nil {
		return nil, err
	}
	for _, f := range flows {
		m := normalizeJSON(maskFlow(f))
		for _, k := range []string{"state", "template", "placement", "placement_reason", "created_at", "updated_at", "created_by", "version"} {
			delete(m, k)
		}
		doc.Flows = append(doc.Flows, m)
	}
	rows, err := s.db.QueryContext(ctx, `SELECT name, type, config, enabled FROM alert_channels ORDER BY name`)
	if err != nil {
		return nil, err
	}
	for rows.Next() {
		var c exportedChannel
		var cfg string
		var enabled int
		if rows.Scan(&c.Name, &c.Type, &cfg, &enabled) != nil {
			continue
		}
		_ = json.Unmarshal([]byte(cfg), &c.Config)
		c.Config, c.Enabled = channels.MaskConfig(c.Type, c.Config), enabled == 1
		doc.Channels = append(doc.Channels, c)
	}
	rows.Close()
	silences, err := s.querySilences(ctx, false)
	if err != nil {
		return nil, err
	}
	for _, sl := range silences {
		doc.Silences = append(doc.Silences, exportedSilence{Name: sl.Name, RuleIDs: sl.RuleIDs,
			StartsAt: sqltime.Format(sl.StartsAt), EndsAt: sqltime.Format(sl.EndsAt)})
	}
	return yaml.Marshal(doc)
}

// ImportSummary compte ce qu'un import a fait ; Errors explique chaque refus.
type ImportSummary struct {
	FlowsCreated    int      `json:"flows_created"`
	FlowsUpdated    int      `json:"flows_updated"`
	FlowsRejected   int      `json:"flows_rejected"`
	ChannelsCreated int      `json:"channels_created"`
	ChannelsUpdated int      `json:"channels_updated"`
	SilencesCreated int      `json:"silences_created"`
	Errors          []string `json:"errors,omitempty"`
}

// Import applique un document au format d'Export. Flux et canaux sont mis à jour par nom ou créés ; les
// mises en sourdine sont toujours ajoutées.
func (s *Service) Import(ctx context.Context, raw []byte, actor string) (*ImportSummary, error) {
	var doc exportDoc
	if err := yaml.Unmarshal(raw, &doc); err != nil {
		return nil, invalid("document illisible : %v", err)
	}
	if doc.Version != exportVersion {
		return nil, invalid("version de document %d non prise en charge (attendue : %d)", doc.Version, exportVersion)
	}
	sum := &ImportSummary{}
	flows := make([]*Flow, 0, len(doc.Flows))
	for _, m := range doc.Flows {
		var f Flow
		b, _ := json.Marshal(normalizeJSON(m))
		if err := json.Unmarshal(b, &f); err != nil || f.Name == "" {
			sum.FlowsRejected++
			sum.Errors = append(sum.Errors, fmt.Sprintf("flux illisible : %v", err))
			continue
		}
		flows = append(flows, &f)
	}
	// Les playbooks d'abord : les flux qui les appellent les trouvent à la validation.
	sort.SliceStable(flows, func(i, j int) bool {
		return flows[i].Trigger.Kind == TriggerManual && flows[j].Trigger.Kind != TriggerManual
	})
	edge := false
	for _, f := range flows {
		created, err := s.importFlow(ctx, f, actor)
		if err != nil {
			sum.FlowsRejected++
			sum.Errors = append(sum.Errors, f.Name+" : "+err.Error())
			continue
		}
		if created {
			sum.FlowsCreated++
		} else {
			sum.FlowsUpdated++
		}
		if p, _ := placement(f); p == PlacementEdge {
			edge = true
		}
	}
	if edge {
		s.edgeChanged()
	}
	s.importChannels(ctx, doc.Channels, sum)
	for _, es := range doc.Silences {
		starts, e1 := sqltime.Parse(es.StartsAt)
		ends, e2 := sqltime.Parse(es.EndsAt)
		if e1 != nil || e2 != nil {
			sum.Errors = append(sum.Errors, es.Name+" : dates illisibles")
			continue
		}
		if _, err := s.CreateSilence(ctx, Silence{Name: es.Name, RuleIDs: es.RuleIDs, StartsAt: starts, EndsAt: ends}); err == nil {
			sum.SilencesCreated++
		}
	}
	return sum, nil
}

func (s *Service) importFlow(ctx context.Context, f *Flow, actor string) (bool, error) {
	var existingID string
	_ = s.db.QueryRowContext(ctx, `SELECT id FROM flows WHERE name=?`, f.Name).Scan(&existingID)
	if existingID != "" {
		old, err := s.getFlow(ctx, existingID)
		if err != nil {
			return false, err
		}
		f.ID, f.CreatedBy, f.Version = old.ID, old.CreatedBy, old.Version+1
		keepSecrets(old, f)
		if err := s.check(ctx, f); err != nil {
			return false, err
		}
		if err := s.updateFlowRow(ctx, f); err != nil {
			return false, err
		}
		s.snapshot(ctx, f, actor)
		return false, nil
	}
	if f.ID == "" {
		f.ID = uuid.NewString()
	} else if _, err := s.getFlow(ctx, f.ID); err == nil {
		f.ID = uuid.NewString() // identifiant déjà pris par un autre flux
	}
	f.Version, f.CreatedBy = 1, actor
	if err := s.check(ctx, f); err != nil {
		return false, err
	}
	if err := s.insertFlow(ctx, f); err != nil {
		return false, err
	}
	s.snapshot(ctx, f, actor)
	return true, nil
}

func (s *Service) importChannels(ctx context.Context, list []exportedChannel, sum *ImportSummary) {
	for _, c := range list {
		if c.Name == "" || c.Type == "" {
			continue
		}
		var id, oldCfg string
		err := s.db.QueryRowContext(ctx, `SELECT id, config FROM alert_channels WHERE name=?`, c.Name).Scan(&id, &oldCfg)
		if err == nil {
			var old map[string]any
			_ = json.Unmarshal([]byte(oldCfg), &old)
			c.Config = channels.KeepConfigSecrets(c.Type, old, c.Config)
		}
		cfg, _ := json.Marshal(c.Config)
		now := sqltime.Format(time.Now())
		if err == nil {
			if _, err := s.db.ExecContext(ctx, `UPDATE alert_channels SET type=?, config=?, enabled=?, updated_at=? WHERE id=?`,
				c.Type, string(cfg), boolInt(c.Enabled), now, id); err == nil {
				sum.ChannelsUpdated++
			}
			continue
		}
		if _, err := s.db.ExecContext(ctx, `INSERT INTO alert_channels (id, name, type, config, enabled) VALUES (?,?,?,?,?)`,
			uuid.NewString(), c.Name, c.Type, string(cfg), boolInt(c.Enabled)); err == nil {
			sum.ChannelsCreated++
		}
	}
}
