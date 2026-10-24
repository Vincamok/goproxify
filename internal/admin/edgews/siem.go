// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package edgews

import (
	"context"
	"encoding/json"
	"sort"
	"sync"
	"time"

	"github.com/vincamok/goproxify/internal/admin/alerting"
	"github.com/vincamok/goproxify/internal/admin/siemcfg"
	"github.com/vincamok/goproxify/internal/edge/siem"
	edgeWS "github.com/vincamok/goproxify/internal/edge/ws"
)

const (
	// siemStale : au-delà, la passerelle n'a pas donné d'état depuis trois envois (30 s) : l'Admin ne le garantit plus.
	siemStale = 90 * time.Second
	// siemAlertEvery : une destination en retard ne re-déclenche l'alerte qu'à cet intervalle.
	siemAlertEvery = 6 * time.Hour
)

type siemNode struct {
	at    time.Time
	dests []siem.DestinationStatus
}

type siemState struct {
	mu      sync.Mutex
	byNode  map[string]siemNode
	alerted map[string]time.Time // « passerelle/destination » → dernière alerte
}

func (m *Manager) handleSIEMStatus(raw json.RawMessage) {
	var p edgeWS.SIEMStatusPayload
	if err := json.Unmarshal(raw, &p); err != nil || p.NodeName == "" {
		return
	}
	now := time.Now()
	m.siem.mu.Lock()
	if m.siem.byNode == nil {
		m.siem.byNode = map[string]siemNode{}
		m.siem.alerted = map[string]time.Time{}
	}
	m.siem.byNode[p.NodeName] = siemNode{at: now, dests: p.Destinations}
	events := siemLateEvents(p.NodeName, p.Destinations, m.siem.alerted, now)
	m.siem.mu.Unlock()
	if m.alertEngine == nil {
		return
	}
	for _, ev := range events {
		m.alertEngine.Emit(ev)
	}
}

// siemLateEvents rend les alertes à émettre : une destination dont le retard dépasse son seuil, ou qui menace des
// lignes de la purge (critique). alerted retient la dernière alerte de chaque destination ; une destination revenue à
// l'heure est oubliée, la prochaine panne alertera tout de suite.
func siemLateEvents(node string, ds []siem.DestinationStatus, alerted map[string]time.Time, now time.Time) []alerting.Event {
	var out []alerting.Event
	live := map[string]bool{}
	for _, d := range ds {
		key := node + "/" + d.ID
		live[key] = true
		if d.LagSec <= int64(d.AlertAfterMin)*60 && !d.AtRisk {
			delete(alerted, key)
			continue
		}
		if last, ok := alerted[key]; ok && now.Sub(last) < siemAlertEvery {
			continue
		}
		alerted[key] = now
		sev := alerting.SevWarning
		if d.AtRisk {
			sev = alerting.SevCritical
		}
		out = append(out, alerting.Event{
			Trigger: alerting.TriggerSIEMExportLag, Severity: sev, NodeName: node, Component: "edge", FiredAt: now,
			Detail: map[string]any{"destination": d.Name, "node_name": node, "lag_min": d.LagSec / 60, "at_risk": d.AtRisk, "error": d.LastError},
		})
	}
	for key := range alerted {
		if len(key) > len(node) && key[:len(node)+1] == node+"/" && !live[key] {
			delete(alerted, key)
		}
	}
	return out
}

// SIEMStatus rend l'état de l'exporteur de chaque passerelle qui en a rapporté un, par nom.
func (m *Manager) SIEMStatus() []siemcfg.NodeStatus {
	m.siem.mu.Lock()
	defer m.siem.mu.Unlock()
	out := make([]siemcfg.NodeStatus, 0, len(m.siem.byNode))
	for node, s := range m.siem.byNode {
		out = append(out, siemcfg.NodeStatus{NodeName: node, ReportedAt: s.at.UTC().Format(time.RFC3339), Stale: time.Since(s.at) > siemStale, Destinations: s.dests})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].NodeName < out[j].NodeName })
	return out
}

// PushSIEMConfig envoie la configuration de l'exporteur SIEM aux passerelles ; chacune en garde une copie chiffrée et
// exporte seule ensuite.
func (m *Manager) PushSIEMConfig(ctx context.Context) {
	cfg := siemcfg.Load(m.db)
	for _, e := range m.allEntries() {
		e := e
		go func() {
			if err := e.client.PushJSON(edgeWS.TypePushSIEMConfig, siemcfg.ForNode(cfg, e.nodeName)); err != nil {
				m.log.Warn("edgews: push siem config", "edge", e.nodeName, "err", err)
			}
		}()
	}
}
