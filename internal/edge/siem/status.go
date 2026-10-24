// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package siem

import (
	"sort"
	"time"
)

// atRiskShare : au-delà de cette part de la conservation, un retard menace des lignes qui vont être purgées.
const atRiskShare = 0.8

// DestinationStatus est l'état d'une destination, envoyé à l'Admin.
type DestinationStatus struct {
	ID    string `json:"id"`
	Name  string `json:"name"`
	Type  string `json:"type"`
	State string `json:"state"` // starting | ok | retrying | stopped
	// LastError et LastErrorAt : dernier échec, vide si la destination va bien.
	LastError   string `json:"last_error,omitempty"`
	LastErrorAt string `json:"last_error_at,omitempty"`
	Delivered   int64  `json:"delivered"`
	LastSent    string `json:"last_sent,omitempty"`
	// LagSec : âge de la plus ancienne ligne pas encore livrée (0 : à jour).
	LagSec int64 `json:"lag_sec"`
	// AtRisk : le retard dépasse 80 % de la conservation : des lignes vont être purgées avant d'être livrées.
	AtRisk        bool `json:"at_risk,omitempty"`
	AlertAfterMin int  `json:"alert_after_min"`
}

// Status rend l'état de chaque destination en cours, par nom.
func (m *Manager) Status() []DestinationStatus {
	m.mu.Lock()
	ws := make([]*worker, 0, len(m.workers))
	for _, w := range m.workers {
		ws = append(ws, w)
	}
	m.mu.Unlock()
	now := m.opts.Now()
	out := make([]DestinationStatus, 0, len(ws))
	for _, w := range ws {
		w.mu.Lock()
		st := DestinationStatus{ID: w.dest.ID, Name: w.dest.Name, Type: w.dest.Type, State: w.state, LastError: w.lastErr, Delivered: w.sent,
			AlertAfterMin: w.dest.AlertAfter()}
		if !w.lastErrAt.IsZero() && w.lastErr != "" {
			st.LastErrorAt = w.lastErrAt.UTC().Format(time.RFC3339)
		}
		if !w.lastOK.IsZero() {
			st.LastSent = w.lastOK.UTC().Format(time.RFC3339)
		}
		w.mu.Unlock()
		for _, k := range allKinds {
			if !w.dest.Wants(string(k)) {
				continue
			}
			rows, err := m.opts.Source.ReadAfter(k, m.position(w.dest.ID, string(k)), 1)
			if err != nil || len(rows) == 0 {
				continue
			}
			lag := now.Sub(rows[0].Ts)
			if lag < 0 {
				lag = 0
			}
			if s := int64(lag.Seconds()); s > st.LagSec {
				st.LagSec = s
			}
			if m.opts.Retention != nil {
				if keep := m.opts.Retention(k); keep > 0 && lag > time.Duration(float64(keep)*atRiskShare) {
					st.AtRisk = true
				}
			}
		}
		out = append(out, st)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
	return out
}
