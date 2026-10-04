// Copyright 2024-2026 Vincamok / GoProxify contributors
// SPDX-License-Identifier: Apache-2.0

package backup

import (
	"sort"
	"sync"
	"time"
)

// Phases d'une sauvegarde en cours.
const (
	PhaseWaiting = "waiting" // une autre sauvegarde est en cours, celle-ci attend son tour
	PhaseExport  = "export"
	PhaseSecrets = "secrets" // secrets, config HA et état des passerelles
	PhaseHistory = "history"
	PhaseEncrypt = "encrypt"
	PhaseVerify  = "verify"
	PhaseStore   = "store"
)

// RunInfo décrit la sauvegarde en cours, et les copies externes encore en route.
type RunInfo struct {
	Name       string    `json:"name,omitempty"`
	Phase      string    `json:"phase,omitempty"`
	StartedAt  time.Time `json:"started_at,omitempty"`
	Delivering []string  `json:"delivering,omitempty"` // destinations en cours d'envoi
}

// LastRun : résultat de la dernière sauvegarde terminée.
type LastRun struct {
	Name  string    `json:"name"`
	OK    bool      `json:"ok"`
	Error string    `json:"error,omitempty"`
	At    time.Time `json:"at"`
}

type runState struct {
	mu         sync.Mutex
	last       *LastRun
	name       string
	phase      string
	started    time.Time
	delivering map[string]int
}

func (r *runState) begin(name string) {
	r.mu.Lock()
	r.name, r.phase, r.started = name, PhaseWaiting, time.Now()
	r.mu.Unlock()
}

func (r *runState) setPhase(p string) {
	r.mu.Lock()
	if r.name != "" {
		r.phase = p
	}
	r.mu.Unlock()
}

func (r *runState) end() {
	r.mu.Lock()
	r.name, r.phase = "", ""
	r.mu.Unlock()
}

func (r *runState) finish(name string, err error) {
	lr := &LastRun{Name: name, OK: err == nil, At: time.Now()}
	if err != nil {
		lr.Error = err.Error()
	}
	r.mu.Lock()
	r.last = lr
	r.mu.Unlock()
}

// LastRun renvoie le résultat de la dernière sauvegarde terminée depuis le démarrage, ou nil.
func (s *Scheduler) LastRun() *LastRun {
	s.run.mu.Lock()
	defer s.run.mu.Unlock()
	return s.run.last
}

func (r *runState) startDelivery(dest string) {
	r.mu.Lock()
	if r.delivering == nil {
		r.delivering = map[string]int{}
	}
	r.delivering[dest]++
	r.mu.Unlock()
}

func (r *runState) endDelivery(dest string) {
	r.mu.Lock()
	if r.delivering[dest]--; r.delivering[dest] <= 0 {
		delete(r.delivering, dest)
	}
	r.mu.Unlock()
}

// Running renvoie l'activité en cours, ou nil si rien ne tourne.
func (s *Scheduler) Running() *RunInfo {
	r := &s.run
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.name == "" && len(r.delivering) == 0 {
		return nil
	}
	info := &RunInfo{Name: r.name, Phase: r.phase, StartedAt: r.started}
	for d := range r.delivering {
		info.Delivering = append(info.Delivering, d)
	}
	sort.Strings(info.Delivering)
	return info
}
